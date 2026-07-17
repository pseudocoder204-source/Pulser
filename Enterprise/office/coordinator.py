#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
mark2 Enterprise -- office one-button audit coordinator (Layers 0-2).

Per Enterprise/Notes/office-audit-plan.txt, this is the boss's single entry point
for an office-wide sweep: he supplies the office CIDR once (and, optionally,
per-OS credentials for the credentialed reach-in track added in a later layer),
and the coordinator is responsible for never touching a host outside that range.

Layer 0: enroll the CIDR, demonstrate per-host token minting is gated by CIDR
containment (Enterprise/core/scope.py), and set up the credential descriptor
shape later layers will consume.

Layer 1 (--discover): turn the enrolled CIDR into a concrete fleet inventory
via Enterprise/office/fleet.py -- host discovery (-sn, MAC-keyed) gated again
per-host through the same CIDR-containment check, then a lightweight
per-host port fingerprint to guess OS and pick a WinRM-vs-SSH transport for
the credentialed reach-in track Layer 2 will add.

Layer 2 (--credential-check): reach into ONE host over its own SSH/WinRM
channel using operator-supplied credentials and run the real native check
(Lynis over SSH, the Windows audit + Defender PowerShell payloads over
WinRM) via Enterprise/office/remote_scan.py -- proves the credentialed
reach-in works end-to-end for a single host, before Layer 3 wires it into
the full fleet loop.

Layer 3/4 (--run-audit): the actual one-button sweep. Fans out the network
track (always-on, zero-credential) plus the credentialed track (where a
transport is reachable) across every in-scope host via
Enterprise/office/fleet_audit.py, then aggregates into one office-wide
summary with a per-host report breakdown and a per-host x per-scanner
coverage matrix.

This is a separate CLI from agent.py's, on purpose: office-audit-plan.txt (line 16)
requires that no file outside Enterprise/ be modified, so this coordinator imports
agent.py and Enterprise/core/scope.py as libraries rather than extending agent.py's
own argparse setup.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Optional

from Enterprise.core.remote_exec import CredentialDescriptor
from Enterprise.core.scope import OfficeScopeError, mint_host_token, resolve_office_scope
from Enterprise.office.fleet import FleetHost, build_fleet_inventory, classify_host, fingerprint_host
from Enterprise.office.fleet_audit import run_fleet_audit
from Enterprise.office.remote_scan import run_credentialed_track


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coordinator.py",
        description="Pulser Enterprise office one-button audit coordinator",
    )
    parser.add_argument(
        "--cidr",
        required=True,
        help="Office network range to enroll, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--ssh-user", default=None, help="SSH username for the credentialed Linux/macOS track"
    )
    parser.add_argument(
        "--ssh-key", default=None, help="Path to an SSH private key for the credentialed track"
    )
    parser.add_argument(
        "--winrm-user", default=None, help="WinRM username for the credentialed Windows track"
    )
    parser.add_argument(
        "--winrm-password", default=None, help="WinRM password for the credentialed Windows track"
    )
    parser.add_argument(
        "--winrm-admin",
        action="store_true",
        help="Assert that --winrm-user is known to hold local admin rights on the "
        "targets it will reach. Defaults to False (fail-safe): without it, "
        "elevation-gated Windows checks (Defender/SMBv1/BitLocker) come back "
        "'undetermined' rather than risking a false 'secure' read.",
    )
    parser.add_argument(
        "--credential-check",
        default=None,
        metavar="IP",
        help="Layer 2 smoke check: mint a token for this IP, fingerprint it to pick "
        "a WinRM/SSH transport (or use --os to skip fingerprinting), and run the "
        "real credentialed hardening/malware check against it",
    )
    parser.add_argument(
        "--os",
        dest="os_override",
        choices=["windows", "posix"],
        default=None,
        help="With --credential-check, skip port fingerprinting and force this OS "
        "(hence transport: windows->WinRM, posix->SSH)",
    )
    parser.add_argument(
        "--check-host",
        default=None,
        help="Layer 0 smoke check: mint a per-host token for this IP and report "
        "whether it falls inside --cidr",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Layer 1: sweep --cidr for live hosts (nmap -sn), fingerprint each "
        "in-scope host's open ports, and classify an OS guess + WinRM/SSH "
        "transport for the later credentialed reach-in track",
    )
    parser.add_argument(
        "--run-audit",
        action="store_true",
        help="Layers 3-4, the actual one-button sweep: discover + classify the fleet, "
        "run the network track on every in-scope host plus the credentialed track "
        "where a transport is reachable, and produce one office-wide report with a "
        "per-host breakdown and coverage matrix",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=8,
        help="With --run-audit: bounded thread-pool size for the per-host sweep (default: 8)",
    )
    parser.add_argument(
        "--per-host-timeout",
        type=int,
        default=60,
        help="With --run-audit: per-host timeout (seconds) for each track (default: 60)",
    )
    parser.add_argument("--json", dest="output_json", action="store_true")
    return parser


def enroll(cidr: str) -> str:
    """Enroll a CIDR for this coordinator run. Raises OfficeScopeError if malformed."""
    return resolve_office_scope(cidr)


def check_host(cidr: str, office_token: str, host_ip: str) -> dict:
    """Layer 0 smoke check: attempt to mint a per-host token, gated by containment."""
    try:
        host_token = mint_host_token(cidr, office_token, host_ip)
    except OfficeScopeError as exc:
        return {"host": host_ip, "in_scope": False, "reason": str(exc)}
    return {"host": host_ip, "in_scope": True, "host_token": host_token}


def credential_check(
    cidr: str,
    office_token: str,
    host_ip: str,
    creds: CredentialDescriptor,
    os_override: Optional[str] = None,
) -> dict:
    """Layer 2 smoke check: mint a token for host_ip (gated by CIDR containment,
    same as check_host), pick a transport, and run the real credentialed
    hardening/malware check against it.
    """
    try:
        mint_host_token(cidr, office_token, host_ip)
    except OfficeScopeError as exc:
        return {"host": host_ip, "in_scope": False, "reason": str(exc)}

    if os_override:
        os_guess = os_override
        transport = "winrm" if os_override == "windows" else "ssh"
    else:
        fingerprint = fingerprint_host(host_ip)
        os_guess, transport = classify_host(fingerprint.get("open_ports", []), vendor=None)

    fleet_host = FleetHost(ip=host_ip, os_guess=os_guess, transport=transport)
    findings = run_credentialed_track(fleet_host, creds)
    return {
        "host": host_ip,
        "in_scope": True,
        "os_guess": os_guess,
        "transport": transport,
        "findings": findings,
    }


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    creds = CredentialDescriptor(
        ssh_user=args.ssh_user,
        ssh_key=args.ssh_key,
        winrm_user=args.winrm_user,
        winrm_password=args.winrm_password,
        winrm_is_admin=args.winrm_admin,
    )

    try:
        office_token = enroll(args.cidr)
    except OfficeScopeError as exc:
        print(f"[coordinator] Error: {exc}", file=sys.stderr)
        sys.exit(1)

    result = {
        "cidr": args.cidr,
        "office_token_minted": True,
        "credentialed_track": {
            "ssh": creds.has_ssh,
            "winrm": creds.has_winrm,
        },
    }

    if args.check_host:
        result["check_host"] = check_host(args.cidr, office_token, args.check_host)

    if args.discover:
        try:
            inventory = build_fleet_inventory(args.cidr, office_token)
        except RuntimeError as exc:
            print(f"[coordinator] Error: {exc}", file=sys.stderr)
            sys.exit(1)
        result["inventory"] = [asdict(host) for host in inventory]

    if args.credential_check:
        result["credential_check"] = credential_check(
            args.cidr, office_token, args.credential_check, creds, os_override=args.os_override
        )

    if args.run_audit:
        result["fleet_audit"] = run_fleet_audit(
            args.cidr, creds, max_workers=args.max_workers, per_host_timeout=args.per_host_timeout
        )

    if args.output_json:
        print(json.dumps(result, indent=2))
        return

    print(f"[coordinator] Enrolled CIDR : {args.cidr}", file=sys.stderr)
    print(
        f"[coordinator] Credentialed track: ssh={creds.has_ssh} winrm={creds.has_winrm}",
        file=sys.stderr,
    )
    if args.check_host:
        check = result["check_host"]
        if check["in_scope"]:
            print(f"[coordinator] {args.check_host}: IN SCOPE (host token minted)")
        else:
            print(f"[coordinator] {args.check_host}: OUT OF SCOPE ({check['reason']})")

    if args.discover:
        print(f"[coordinator] Fleet inventory ({len(result['inventory'])} host(s)):")
        print(f"{'ip':<16}{'mac':<19}{'vendor':<20}{'hostname':<20}{'os_guess':<10}{'transport':<10}")
        for host in result["inventory"]:
            print(
                f"{host['ip'] or '-':<16}{host['mac'] or '-':<19}"
                f"{(host['vendor'] or '-')[:18]:<20}{(host['hostname'] or '-')[:18]:<20}"
                f"{host['os_guess']:<10}{host['transport'] or '-':<10}"
            )

    if args.credential_check:
        check = result["credential_check"]
        if not check["in_scope"]:
            print(f"[coordinator] {args.credential_check}: OUT OF SCOPE ({check['reason']})")
        else:
            print(
                f"[coordinator] {args.credential_check}: os_guess={check['os_guess']} "
                f"transport={check['transport']}"
            )
            print(json.dumps(check["findings"], indent=2))

    if args.run_audit:
        audit = result["fleet_audit"]
        summary = audit["fleet_summary"]
        print(
            f"[coordinator] Fleet audit: {summary['assessed_hosts']}/{summary['total_hosts']} "
            f"host(s) assessed, {summary['errored_hosts']} error(s), "
            f"worst overall risk: {summary['worst_overall_risk']}"
        )
        for ip, host in audit["hosts"].items():
            if host["status"] != "ok":
                print(f"[coordinator]   {ip}: ERROR ({host.get('reason', 'unknown')})")
                continue
            risk = host["report"].get("fix_now", {}).get("overall_risk", "unknown")
            coverage = audit["coverage_matrix"].get(ip, {})
            print(
                f"[coordinator]   {ip}: os={host['os_guess']} transport={host['transport'] or '-'} "
                f"risk={risk} coverage={coverage}"
            )

    if not args.check_host and not args.discover and not args.credential_check and not args.run_audit:
        print(
            "[coordinator] No fleet discovery yet -- pass --check-host to "
            "smoke-test the CIDR containment gate, --discover to sweep --cidr "
            "for a fleet inventory, --credential-check IP to run a real "
            "hardening/malware check against one host, or --run-audit for the "
            "full one-button fleet sweep."
        )


if __name__ == "__main__":
    main()
