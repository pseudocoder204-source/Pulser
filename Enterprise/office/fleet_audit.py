#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier fleet audit -- Layer 3 (aggregation) + Layer 4 (drift/triage/report).

This is the "one button" office-audit-plan.txt describes: enroll a CIDR
(Layer 0), discover + classify the fleet (Layer 1), and for every in-scope
host run the always-on network track plus -- where a credentialed transport
is reachable -- the hardening/malware track (Layer 2), then turn each host's
raw results into a full report via Enterprise/office/host_report.py and roll
all of it up into one office-wide summary with a per-host breakdown.

Nothing outside Enterprise/ is touched; everything here calls existing,
unmodified code (agent.py, core/*, Enterprise/office/fleet.py,
Enterprise/office/remote_scan.py) -- this module is pure orchestration.
"""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional

import agent
from Enterprise.core.remote_exec import CredentialDescriptor
from Enterprise.core.scope import OfficeScopeError, mint_host_token, resolve_office_scope
from Enterprise.office.fleet import FleetHost, build_fleet_inventory
from Enterprise.office.host_report import build_host_results, run_host_pipeline
from Enterprise.office.network_track import run_network_track
from Enterprise.office.remote_scan import run_credentialed_track

__all__ = ["run_fleet_audit", "build_coverage_matrix", "summarize_fleet"]

_DEFAULT_MAX_WORKERS = 8
_DEFAULT_PER_HOST_TIMEOUT = 60


def _audit_one_host(
    host: FleetHost,
    cidr: str,
    office_token: str,
    cred: CredentialDescriptor,
    report_llm,
    db_path: Optional[str],
    per_host_timeout: int,
) -> Dict[str, Any]:
    """Run the full network + (optional) credentialed track for one host and
    build its report. One host's exception degrades to a {"status": "error"}
    entry -- it must never abort the fleet sweep, same discipline as
    agent.py's own per-worker try/except.
    """
    ip = host.ip
    try:
        mint_host_token(cidr, office_token, ip)
    except OfficeScopeError as exc:
        return {"ip": ip, "status": "error", "reason": f"scope check failed: {exc}"}

    try:
        network_result = run_network_track(ip)

        credentialed_result = None
        if host.transport:
            credentialed_result = run_credentialed_track(host, cred, timeout=per_host_timeout)

        raw_results = build_host_results(network_result, credentialed_result)
        pipeline_out = run_host_pipeline(ip, raw_results, report_llm, db_path=db_path)
    except Exception as exc:
        return {"ip": ip, "status": "error", "reason": str(exc)}

    return {
        "ip": ip,
        "status": "ok",
        "os_guess": host.os_guess,
        "transport": host.transport,
        "report": pipeline_out["report"],
        "scanner_status": pipeline_out["scanner_status"],
    }


def run_fleet_audit(
    cidr: str,
    cred: CredentialDescriptor,
    db_path: Optional[str] = None,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    per_host_timeout: int = _DEFAULT_PER_HOST_TIMEOUT,
) -> Dict[str, Any]:
    """Layer 3/4 entry point: enroll -> discover/classify -> per-host network +
    credentialed track -> aggregate. Returns:

        {"cidr", "hosts": {ip: {...per-host result...}},
         "coverage_matrix": {...}, "fleet_summary": {...}}

    "ONE office report + per-host breakdown" per office-audit-plan.txt.
    """
    office_token = resolve_office_scope(cidr)
    inventory = build_fleet_inventory(cidr, office_token)

    # One LLM instance shared across all hosts -- report generation is the
    # only LLM step in the pipeline (agent.py's own design), and instantiating
    # a fresh client per host would be pure overhead.
    report_llm = agent._get_report_llm()

    hosts: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_host = {
            pool.submit(
                _audit_one_host, host, cidr, office_token, cred, report_llm, db_path, per_host_timeout
            ): host
            for host in inventory
            if host.ip and host.status != "out_of_scope"
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover -- _audit_one_host already catches
                print(f"[fleet_audit] {host.ip}: unexpected error: {exc}", file=sys.stderr)
                result = {"ip": host.ip, "status": "error", "reason": str(exc)}
            hosts[result["ip"]] = result

    coverage_matrix = build_coverage_matrix(hosts)
    fleet_summary = summarize_fleet(hosts)

    return {
        "cidr": cidr,
        "hosts": hosts,
        "coverage_matrix": coverage_matrix,
        "fleet_summary": fleet_summary,
    }


def build_coverage_matrix(hosts: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """Per-host x per-scanner coverage, gathered from each host's own
    scanner_status (agent.scanner_status_map's output). A host whose sweep
    errored outright gets a single "error" entry -- it never gets read as
    "clean" for scanners that never ran, the same load-bearing invariant
    CLAUDE.md documents for the local single-target spine.
    """
    matrix: Dict[str, Dict[str, str]] = {}
    for ip, result in hosts.items():
        if result.get("status") != "ok":
            matrix[ip] = {"_sweep": "error"}
            continue
        matrix[ip] = dict(result.get("scanner_status", {}))
    return matrix


def summarize_fleet(hosts: Dict[str, Any]) -> Dict[str, Any]:
    """Small, deterministic (no LLM) fleet-wide rollup: host counts and the
    single worst overall_risk seen across the fleet's "fix now" sections --
    mirrors agent.py's own deterministic-only triage/aggregation ethos.
    """
    total = len(hosts)
    ok = sum(1 for r in hosts.values() if r.get("status") == "ok")
    errored = total - ok

    worst_tier = 0
    worst_risk = "low"
    hosts_by_risk: Dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}

    for ip, result in hosts.items():
        if result.get("status") != "ok":
            continue
        fix_now = result.get("report", {}).get("fix_now", {})
        risk = str(fix_now.get("overall_risk", "low")).lower()
        if risk not in hosts_by_risk:
            risk = "low"
        hosts_by_risk[risk].append(ip)
        tier = agent._TIER_RANK.get(risk, 0)
        if tier > worst_tier:
            worst_tier = tier
            worst_risk = risk

    return {
        "total_hosts": total,
        "assessed_hosts": ok,
        "errored_hosts": errored,
        "worst_overall_risk": worst_risk if ok else "unknown",
        "hosts_by_risk": hosts_by_risk,
    }
