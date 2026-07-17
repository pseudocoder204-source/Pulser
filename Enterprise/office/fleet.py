#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier fleet enumeration (Layer 1).

Per Enterprise/Notes/office-audit-plan.txt Layer 1, this module turns an
enrolled CIDR (Enterprise/core/scope.py) into a concrete host inventory, so
that a later credentialed reach-in layer (Layer 2) knows which transport
(WinRM vs SSH) to attempt on each host.

Everything here is reuse of existing, UNMODIFIED scanner code — no new nmap
flags, no subgraph changes, nothing outside Enterprise/ touched:

  - discover_fleet()   calls scanners.nmap.nmap_subgraph.run_pipeline(...,
                        scan_type="host_discovery") directly -- the same call
                        core/tools.py::discover_hosts makes internally.
  - fingerprint_host()  calls scanners.nmap.nmap_parser.run_nmap() +
                        parse_nmap_xml() directly with ScanType.QUICK_SYN --
                        bypassing the subgraph's DB-backed enrich step
                        entirely, since this only needs open port numbers,
                        not CVE data.

OS fingerprinting note: office-audit-plan.txt assumes nmap OS/service
detection is "already available" for picking WinRM vs SSH. In practice
scanners/nmap/nmap_parser.py has no -O-flag ScanType, and its CPE-based OS
matcher (parse_nmap_os_cpes) only fires off a VERSION_DETECT (-sV) scan
that's already tied to CVE enrichment -- too heavy for a 30-40 host sweep,
and ScanType lives outside Enterprise/ so it can't be extended anyway. This
module instead uses a lightweight, well-known port-based heuristic (RDP/SMB
-> Windows, port 22 -> POSIX) computed from a QUICK_SYN scan, matching this
codebase's existing pattern of degrading gracefully when a capability isn't
present rather than reaching outside Enterprise/ to add it.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from Enterprise.core.scope import OfficeScopeError, mint_host_token
from scanners.nmap.nmap_parser import ScanType, parse_nmap_xml, run_nmap
from scanners.nmap.nmap_subgraph import run_pipeline as run_nmap_pipeline

__all__ = [
    "FleetHost",
    "discover_fleet",
    "fingerprint_host",
    "classify_host",
    "build_fleet_inventory",
]

# Ports whose presence is a strong, standard signal of a Windows remote-admin
# surface: RDP (3389), WinRM (5985/5986), RPC endpoint mapper (135), NetBIOS
# session (139), SMB (445).
_WINDOWS_PORTS = {3389, 5985, 5986, 135, 139, 445}
_SSH_PORT = 22

_DEFAULT_FINGERPRINT_TIMEOUT = 60
_DEFAULT_MAX_WORKERS = 8


@dataclass
class FleetHost:
    ip: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "unknown"
    open_ports: List[int] = field(default_factory=list)
    os_guess: str = "unknown"
    transport: Optional[str] = None


def discover_fleet(cidr: str, db_path: str = "vulnerability_cache.db") -> List[Dict[str, Any]]:
    """Host-discovery sweep of `cidr` (-sn, MAC-keyed). Reuses the same nmap
    subgraph call core/tools.py::discover_hosts makes -- called directly here
    rather than through the @tool wrapper, since this is invoked by the
    coordinator's own code, not the LLM.

    Returns a list of HostFinding dicts (ip, mac, vendor, hostname, status).
    Raises RuntimeError if nmap is not installed (mirrors run_nmap's own
    failure signal).
    """
    payload = run_nmap_pipeline(
        cidr,
        scan_type="host_discovery",
        db_path=db_path,
        skip_sync=True,
    )
    return payload if isinstance(payload, list) else []


def fingerprint_host(ip: str, timeout: int = _DEFAULT_FINGERPRINT_TIMEOUT) -> Dict[str, Any]:
    """Lightweight per-host QUICK_SYN scan for open ports only -- no CVE
    enrichment, no DB dependency. One unreachable/slow host degrades to an
    empty port list rather than aborting the fleet sweep.
    """
    try:
        xml = run_nmap(ip, ScanType.QUICK_SYN, timeout=timeout)
    except RuntimeError as exc:
        return {"open_ports": [], "error": str(exc)}

    try:
        findings = parse_nmap_xml(xml)
    except Exception as exc:  # malformed/partial XML from a timed-out scan
        return {"open_ports": [], "error": str(exc)}

    return {"open_ports": sorted({f.port for f in findings if f.state == "open"})}


def classify_host(open_ports: List[int], vendor: Optional[str]) -> Tuple[str, Optional[str]]:
    """Pure heuristic: open_ports + vendor OUI string -> (os_guess, transport).

    transport is None when nothing usable was observed -- Layer 2 must never
    attempt a credentialed reach-in against a host with no signal; it stays
    on the network-only track.
    """
    ports = set(open_ports)
    if ports & _WINDOWS_PORTS:
        return "windows", "winrm"
    if _SSH_PORT in ports:
        return "posix", "ssh"
    if vendor and "apple" in vendor.lower():
        return "posix", "ssh"
    return "unknown", None


def build_fleet_inventory(
    cidr: str,
    office_token: str,
    db_path: str = "vulnerability_cache.db",
    max_workers: int = _DEFAULT_MAX_WORKERS,
    per_host_timeout: int = _DEFAULT_FINGERPRINT_TIMEOUT,
) -> List[FleetHost]:
    """Layer 1 entry point: discover -> CIDR-containment gate -> fingerprint
    -> classify. Fingerprinting runs concurrently under a bounded worker pool
    (a first cut of the "bounded pool, per-host timeout" discipline Layer 3
    formalizes across the whole audit, not just discovery).
    """
    raw_hosts = discover_fleet(cidr, db_path=db_path)

    in_scope: List[Dict[str, Any]] = []
    out_of_scope: List[FleetHost] = []
    for host in raw_hosts:
        ip = host.get("ip")
        if not ip:
            continue
        try:
            mint_host_token(cidr, office_token, ip)
        except OfficeScopeError as exc:
            print(f"[fleet] {ip}: dropped, outside enrolled CIDR ({exc})", file=sys.stderr)
            out_of_scope.append(
                FleetHost(
                    ip=ip,
                    mac=host.get("mac"),
                    vendor=host.get("vendor"),
                    hostname=host.get("hostname"),
                    status="out_of_scope",
                )
            )
            continue
        in_scope.append(host)

    results: List[FleetHost] = list(out_of_scope)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_host = {
            pool.submit(fingerprint_host, host["ip"], per_host_timeout): host
            for host in in_scope
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            fp = future.result()
            os_guess, transport = classify_host(fp.get("open_ports", []), host.get("vendor"))
            results.append(
                FleetHost(
                    ip=host.get("ip"),
                    mac=host.get("mac"),
                    vendor=host.get("vendor"),
                    hostname=host.get("hostname"),
                    status=host.get("status", "unknown"),
                    open_ports=fp.get("open_ports", []),
                    os_guess=os_guess,
                    transport=transport,
                )
            )

    return results
