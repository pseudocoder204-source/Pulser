#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier credentialed reach-in (Layer 2).

Per Enterprise/Notes/office-audit-plan.txt Layer 2, this module is the reuse
layer sitting on top of Enterprise/core/remote_exec.py's transport: it knows
WHAT command to run on a host and WHICH existing, unmodified scanner parser
to hand the result to.

Nothing in scanners/ is modified. Each scanner's run -> parse -> build stages
are already decoupled (confirmed by reading the source): the PowerShell
payloads for the two Windows scanners are module-level string constants, and
every parse_*/build_* function takes raw text and doesn't care how that text
was obtained. So this module imports those constants and functions verbatim,
and only supplies a different way of running the command -- remote_exec.run_remote
(SSH/WinRM) instead of the local subprocess.run each parser's own run_* uses.

Linux/macOS coverage runs the SAME `lynis audit system` the local host_audit
stage runs (not a hand-rolled substitute) -- Lynis already supports macOS as
well as Linux, and a missing binary on a given target is reported as
"not_assessed" with a clear reason rather than silently downgraded to a
weaker check. (A future opt-in installer -- deferred in office-audit-plan.txt
-- is the intended way to guarantee `lynis` is present on company-owned
targets ahead of a sweep; this module doesn't provision anything itself.)

Remote ClamAV is deliberately NOT included here: the existing ClamAV pipeline
(scanners/clamav/clamav_parser.py) is a producer/consumer design specifically
because a full scan takes 1-4+ hours and depends on a LOCAL incremental-scan
manifest (mtime/size/inode diffing against clamav_manifest.db) that doesn't
translate to a bounded, sweep-time SSH call without a host-keyed, remote-aware
redesign of that manifest -- a separate piece of work. Linux/macOS malware
coverage stays "not_assessed" here; Windows keeps live Defender coverage,
which already runs instantly with no manifest involved.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from Enterprise.core.remote_exec import CredentialDescriptor, run_remote
from Enterprise.office.fleet import FleetHost

from scanners.lynis.lynis_parser import (
    DEFAULT_LYNIS_TIMEOUT,
    build_llm_payload_from_lynis,
    parse_lynis_report,
)
from scanners.lynis.lynis_subgraph import LYNIS_TEST_CATALOG, _infer_category
from scanners.windows.windows_audit_parser import (
    _AUDIT_PS_SCRIPT,
    DEFAULT_AUDIT_TIMEOUT,
    build_llm_payload_from_windows_audit,
    parse_windows_audit,
)
from scanners.windows.windows_defender_parser import (
    _DEFENDER_PS_SCRIPT,
    DEFAULT_DEFENDER_TIMEOUT,
    build_llm_payload_from_defender,
    parse_defender_output,
)

__all__ = [
    "run_windows_audit_remote",
    "run_defender_remote",
    "run_linux_hardening_remote",
    "run_credentialed_track",
]

_NOT_ASSESSED_NO_TRANSPORT = {
    "status": "not_assessed",
    "reason": "no reachable credentialed transport",
}
_NOT_ASSESSED_NO_REMOTE_CLAMAV = {
    "status": "not_assessed",
    "reason": (
        "remote ClamAV deferred -- existing design is a producer/consumer, "
        "manifest-based background scan (1-4+ hrs), not a sweep-time operation"
    ),
}

# Same report-file path scanners/lynis/lynis_parser.py::run_lynis_audit defaults
# to locally -- kept as a literal here rather than importing the module's
# private _DEFAULT_REPORT_FILE constant.
_LYNIS_REPORT_FILE = "/tmp/lynis-report.dat"
_LYNIS_NOT_FOUND_SENTINEL = "__LYNIS_NOT_FOUND__"


def _transport_error(result_status: str, error: Optional[str]) -> Dict[str, Any]:
    return {"status": result_status, "reason": error or result_status}


def run_windows_audit_remote(
    host: str, cred: CredentialDescriptor, timeout: int = DEFAULT_AUDIT_TIMEOUT
) -> Dict[str, Any]:
    """Windows hardening audit, run over WinRM. Reuses windows_audit_parser's
    exact PowerShell payload and parse/build functions unmodified.
    """
    result = run_remote(host, "windows", cred, _AUDIT_PS_SCRIPT, timeout)
    if result.status != "ok":
        return _transport_error(result.status, result.error)
    if not result.stdout.strip():
        return {"status": "error", "reason": "empty response from remote host"}

    facts = parse_windows_audit(result.stdout)
    return build_llm_payload_from_windows_audit(facts, elevated=cred.winrm_is_admin)


def run_defender_remote(
    host: str, cred: CredentialDescriptor, timeout: int = DEFAULT_DEFENDER_TIMEOUT
) -> Dict[str, Any]:
    """Windows Defender threat history, run over WinRM. Reuses
    windows_defender_parser's exact PowerShell payload and parse/build
    functions unmodified.
    """
    result = run_remote(host, "windows", cred, _DEFENDER_PS_SCRIPT, timeout)
    if result.status != "ok":
        return _transport_error(result.status, result.error)
    if not result.stdout.strip():
        return {"status": "error", "reason": "empty response from remote host"}

    parsed = parse_defender_output(result.stdout)
    return build_llm_payload_from_defender(parsed)


def _enrich_lynis_findings(findings):
    enriched = []
    for finding in findings:
        test_id = finding.get("test_id", "")
        meta = LYNIS_TEST_CATALOG.get(test_id, {})
        entry = dict(finding)
        entry["category"] = meta.get("category", _infer_category(test_id))
        if not entry.get("description") or entry["description"] in ("-", ""):
            entry["description"] = meta.get("description", "")
        if not entry.get("solution") or entry["solution"] in ("-", ""):
            entry["solution"] = meta.get("solution", "")
        enriched.append(entry)
    return enriched


def run_linux_hardening_remote(
    host: str, cred: CredentialDescriptor, timeout: int = DEFAULT_LYNIS_TIMEOUT
) -> Dict[str, Any]:
    """Linux/macOS hardening audit, run over SSH -- the same `lynis audit
    system` the local host_audit stage runs, not a hand-rolled substitute.
    Reuses parse_lynis_report/build_llm_payload_from_lynis unmodified, and
    replicates lynis_subgraph.py's small catalog-enrichment step (that
    node is private/LangGraph-state-shaped, not meant for external reuse --
    see this module's docstring) using the public LYNIS_TEST_CATALOG.
    """
    command = (
        f"command -v lynis >/dev/null 2>&1 && "
        f"lynis audit system --quick --no-colors --report-file {_LYNIS_REPORT_FILE} "
        f">/dev/null 2>&1 && cat {_LYNIS_REPORT_FILE} || echo '{_LYNIS_NOT_FOUND_SENTINEL}'"
    )
    result = run_remote(host, "posix", cred, command, timeout)
    if result.status != "ok":
        return _transport_error(result.status, result.error)

    if _LYNIS_NOT_FOUND_SENTINEL in result.stdout:
        return {"status": "not_assessed", "reason": "lynis not installed on target"}
    if not result.stdout.strip():
        return {"status": "error", "reason": "empty response from remote host"}

    parsed = parse_lynis_report(result.stdout)
    parsed["warnings"] = _enrich_lynis_findings(parsed.get("warnings", []))
    parsed["suggestions"] = _enrich_lynis_findings(parsed.get("suggestions", []))
    return build_llm_payload_from_lynis(parsed)


def run_credentialed_track(
    fleet_host: FleetHost, cred: CredentialDescriptor, timeout: Optional[int] = None
) -> Dict[str, Any]:
    """Layer 2 entry point: dispatch a discovered host to its credentialed
    reach-in track based on the transport Layer 1 classified it into.

    `timeout`, if given, overrides each stage's own default (DEFAULT_AUDIT_TIMEOUT
    / DEFAULT_DEFENDER_TIMEOUT / DEFAULT_LYNIS_TIMEOUT) rather than stacking a
    separate cap on top of them.

    A host with no usable transport is EXPLICITLY not_assessed for both
    hardening and malware -- never silently read as "clean", same rule
    CLAUDE.md states for the local scanner-status coverage matrix.
    """
    if fleet_host.transport == "winrm":
        return {
            "hardening": run_windows_audit_remote(
                fleet_host.ip, cred, timeout=timeout or DEFAULT_AUDIT_TIMEOUT
            ),
            "malware": run_defender_remote(
                fleet_host.ip, cred, timeout=timeout or DEFAULT_DEFENDER_TIMEOUT
            ),
        }
    if fleet_host.transport == "ssh":
        return {
            "hardening": run_linux_hardening_remote(
                fleet_host.ip, cred, timeout=timeout or DEFAULT_LYNIS_TIMEOUT
            ),
            "malware": dict(_NOT_ASSESSED_NO_REMOTE_CLAMAV),
        }
    return {
        "hardening": dict(_NOT_ASSESSED_NO_TRANSPORT),
        "malware": dict(_NOT_ASSESSED_NO_TRANSPORT),
    }
