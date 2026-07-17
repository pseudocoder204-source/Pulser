#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier remote-exec transport (Layer 2).

Per Enterprise/Notes/office-audit-plan.txt Layer 2, this is "the one genuinely
new capability" the office audit needs: reach into a discovered host over its
own OS-native remote-admin channel (WinRM for Windows, SSH for Linux/macOS)
using operator-supplied credentials, run a command, and get its raw stdout
back — without installing anything on the target.

This module is deliberately dumb: it knows nothing about nmap, Lynis, or
PowerShell audit payloads. It just runs a command over SSH or WinRM and
reports what happened. Enterprise/office/remote_scan.py is the layer that
feeds specific commands in and hands the raw stdout to the EXISTING,
unmodified scanner parsers (see that module's docstring for why nothing
outside Enterprise/ needs to change to make that reuse work).

Mirrors scanners/nmap/nmap_parser.py::run_nmap's hard-timeout + never-raise
discipline: a connection failure, auth failure, or timeout against one host
downgrades to a status string on the returned RemoteExecResult -- it never
raises out to the caller, because a single unreachable host must not abort
an office-wide sweep. Missing paramiko/pywinrm (not installed) downgrades to
status="unavailable", the same shape this codebase already uses for a
missing nmap/trivy binary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = ["CredentialDescriptor", "RemoteExecResult", "run_remote"]


@dataclass
class CredentialDescriptor:
    """Optional per-OS credential for the credentialed reach-in track.

    Deliberately ONE shared credential per protocol for the whole sweep (not
    per-host) -- see office-audit-plan.txt's "Trust = existing OS
    credentials" decision. Hosts the supplied credential can't reach fall
    back to network-only findings; that's accepted, correct behavior for
    BYOD/home machines, not a bug. A future opt-in installer for
    COMPANY-OWNED laptops (push-based subagent instead of credentialed
    reach-in) is noted as deferred in office-audit-plan.txt for fleets where
    a single shared credential can't cover enough of the fleet.
    """

    ssh_user: Optional[str] = None
    ssh_key: Optional[str] = None
    winrm_user: Optional[str] = None
    winrm_password: Optional[str] = None
    # Whether the WinRM account is known to hold local admin rights on the
    # target. NOTE: this does NOT gate whether Defender/SMBv1/BitLocker
    # findings are trusted -- that gate is entirely server-side. The remote
    # PowerShell session either comes back with a real value for a given
    # elevation-gated check (because the account genuinely has an elevated
    # token on the target -- WinRM sessions for local Administrators get one
    # automatically, no interactive UAC prompt involved) or it comes back
    # null, in which case _evaluate_findings() (windows_audit_parser.py)
    # reports "undetermined" regardless of this flag. So the fail-safe
    # property ("never a false 'secure' read") already holds unconditionally,
    # for any credential, with no action needed from the operator.
    #
    # All this flag actually changes is the wording of an already-undetermined
    # finding's hint text (build_llm_payload_from_windows_audit's `elevated`
    # param, passed straight to windows_audit_parser.py::_undetermined):
    # "could not be determined" vs. "...re-run the audit as Administrator".
    # It exists only so that hint doesn't misleadingly suggest re-running as
    # Administrator when the operator already knows the account IS an admin
    # and the null reading came from something else (e.g. a locked-down
    # execution policy). Passed explicitly rather than left to
    # build_llm_payload_from_windows_audit's own default, which falls back to
    # checking the CALLER's local elevation -- meaningless for a remote host.
    winrm_is_admin: bool = False

    @property
    def has_ssh(self) -> bool:
        return bool(self.ssh_user and self.ssh_key)

    @property
    def has_winrm(self) -> bool:
        return bool(self.winrm_user and self.winrm_password)


@dataclass
class RemoteExecResult:
    stdout: str = ""
    status: str = "ok"  # "ok" | "unreachable" | "auth_error" | "timeout" | "unavailable"
    error: Optional[str] = None


def _run_ssh(host: str, cred: CredentialDescriptor, command: str, timeout: int) -> RemoteExecResult:
    try:
        import paramiko
    except ImportError:
        return RemoteExecResult(status="unavailable", error="paramiko is not installed")

    if not cred.has_ssh:
        return RemoteExecResult(status="auth_error", error="no SSH credential supplied")

    client = paramiko.SSHClient()
    # No host-key pinning: this mirrors the "trust = existing OS credentials"
    # model the plan already accepts for WinRM/Kerberos-NTLM -- the supplied
    # key/login is the proof, not a separate PKI. Flagged here, not silently
    # assumed: a stricter deployment can swap this policy without touching
    # anything else in this module.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            username=cred.ssh_user,
            key_filename=cred.ssh_key,
            timeout=timeout,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        return RemoteExecResult(stdout=out, status="ok")
    except paramiko.AuthenticationException as exc:
        return RemoteExecResult(status="auth_error", error=str(exc))
    except (TimeoutError, paramiko.ssh_exception.SSHException) as exc:
        return RemoteExecResult(status="timeout", error=str(exc))
    except OSError as exc:
        return RemoteExecResult(status="unreachable", error=str(exc))
    except Exception as exc:  # one bad host must never abort the sweep
        return RemoteExecResult(status="unreachable", error=str(exc))
    finally:
        client.close()


def _run_winrm(host: str, cred: CredentialDescriptor, command: str, timeout: int) -> RemoteExecResult:
    try:
        import winrm
    except ImportError:
        return RemoteExecResult(status="unavailable", error="pywinrm is not installed")

    if not cred.has_winrm:
        return RemoteExecResult(status="auth_error", error="no WinRM credential supplied")

    try:
        session = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(cred.winrm_user, cred.winrm_password),
            transport="ntlm",
            operation_timeout_sec=timeout,
            read_timeout_sec=timeout + 5,
        )
        result = session.run_ps(command)
    except Exception as exc:  # winrm's exception surface is broad and version-dependent
        message = str(exc)
        lowered = message.lower()
        # pywinrm/requests-ntlm's actual error text for bad creds is
        # "the specified credentials were rejected by the server" -- it
        # contains none of "auth"/"401", so a plain substring check on those
        # alone mislabels a real auth failure as "unreachable" (misleading:
        # it implies a network problem when the connection actually
        # succeeded and only the login was rejected).
        if any(s in lowered for s in ("auth", "401", "credentials", "access is denied", "access denied")):
            return RemoteExecResult(status="auth_error", error=message)
        return RemoteExecResult(status="unreachable", error=message)

    out = result.std_out.decode("utf-8", errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out)
    if result.status_code != 0 and not out.strip():
        err = result.std_err.decode("utf-8", errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err)
        return RemoteExecResult(status="unreachable", error=err or f"exit code {result.status_code}")
    return RemoteExecResult(stdout=out, status="ok")


def run_remote(
    host: str,
    os_kind: str,
    cred: CredentialDescriptor,
    command: str,
    timeout: int = 120,
) -> RemoteExecResult:
    """Run `command` on `host` over SSH (os_kind="posix") or WinRM
    (os_kind="windows") using `cred`. Never raises -- callers can rely on
    `result.status` alone.
    """
    if os_kind == "windows":
        return _run_winrm(host, cred, command, timeout)
    if os_kind == "posix":
        return _run_ssh(host, cred, command, timeout)
    return RemoteExecResult(status="unreachable", error=f"unknown os_kind: {os_kind!r}")
