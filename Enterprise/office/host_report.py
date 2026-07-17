#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier per-host report pipeline (Layer 3/4 building block).

agent.py's enrich -> drift -> intel -> triage -> persist -> report sequence
is implemented as closures inside agent._build_graph(report_llm)
(agent.py:894-1004), so it cannot be imported and called directly. Every
function those closures call, though, is a plain module-level function:
agent.build_findings_table, agent.scanner_status_map, core.drift.compute_drift,
core.priority.build_intel_map/rank/ordered_refs, agent._split_by_band,
core.scan_log_db.get_last_scan/save_scan_log, agent._resolved_status_overrides,
agent.run_report, agent._attach_drift_markers, agent._resolved_report,
agent._drift_header. This module calls those same functions in the same
order, once per fleet host, using the host's IP as the `target` string
throughout -- exactly the reuse-over-import move
Enterprise/office/remote_scan.py already makes for lynis_subgraph's private
catalog-enrichment step (see that module's docstring for the same rationale).

Using host_ip as `target` means drift/history need zero schema changes:
core/scan_log_db.py's tables already carry `target` as a plain TEXT column
(finding_state's primary key is (target, finding_key)), so N fleet hosts is
just N distinct `target` values as more rows in the same file -- not a
table per host.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import agent
from core import drift as drift_engine
from core import exploit_intel, priority
from core.scan_log_db import get_last_scan, save_scan_log

__all__ = ["build_host_results", "run_host_pipeline"]

_NOT_ASSESSED_NO_TRANSPORT = {
    "status": "not_assessed",
    "reason": "no reachable credentialed transport",
}
_NOT_ASSESSED_NO_REMOTE_FILESYSTEM = {
    "status": "not_assessed",
    "reason": "remote filesystem scan not implemented (Trivy has no sweep-time remote path)",
}


def build_host_results(
    network_result: Dict[str, Any],
    credentialed_result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the exact `raw_results` shape agent.build_findings_table expects,
    from a fleet host's network-track output and (if a transport was reachable)
    its credentialed-track output (Enterprise/office/remote_scan.run_credentialed_track's
    {"hardening":.., "malware":..} shape).

    `credentialed_result` is None for a host with no usable transport (Layer 1
    classified it as unknown) -- host_audit/malware both become explicit
    not_assessed dicts, never silently "ok".
    """
    if credentialed_result is None:
        host_audit = dict(_NOT_ASSESSED_NO_TRANSPORT)
        malware = dict(_NOT_ASSESSED_NO_TRANSPORT)
    else:
        host_audit = credentialed_result.get("hardening", dict(_NOT_ASSESSED_NO_TRANSPORT))
        malware = credentialed_result.get("malware", dict(_NOT_ASSESSED_NO_TRANSPORT))

    return {
        "network": network_result.get("network"),
        "iot_defaults": network_result.get("iot_defaults"),
        "filesystem": dict(_NOT_ASSESSED_NO_REMOTE_FILESYSTEM),
        "host_audit": host_audit,
        "malware": malware,
        "web": network_result.get("web"),
    }


def run_host_pipeline(
    host_ip: str,
    raw_results: Dict[str, Any],
    report_llm,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Replicate agent.py's enrich->drift->intel->triage->persist->report
    sequence for ONE host, keyed by host_ip as `target`.

    Returns {"report": <same shape agent.run_agent() returns>,
             "scanner_status": .., "findings_table": ..} -- the latter two
    feed the fleet-wide coverage matrix in Enterprise/office/fleet_audit.py.
    """
    scan_log_db_path = db_path or agent._scan_log_db_path()
    vuln_db_path = agent._vuln_cache_db_path()

    findings_table = agent.build_findings_table(raw_results)
    scanner_status = agent.scanner_status_map(raw_results)

    records = drift_engine.compute_drift(host_ip, findings_table, scanner_status, scan_log_db_path)
    for finding in findings_table:
        rec = records.get(finding["finding_key"])
        if rec is None:
            continue
        finding["drift_status"] = rec["status"]
        finding["age_days"] = rec["age_days"]
        finding["first_seen"] = rec["first_seen"]
        finding["reappearance_count"] = rec["reappearance_count"]

    resolved_findings = [
        rec["snapshot"]
        for rec in records.values()
        if rec["status"] == drift_engine.STATUS_RESOLVED_ and rec.get("snapshot")
    ]

    # Both syncs swallow their own network/parse failures and leave the
    # existing cache untouched rather than raising (exploit_intel.py's own
    # module docstring) -- an enrichment feed must never become a hard
    # dependency for one host to block the whole fleet sweep.
    exploit_intel.sync_exploit_intel(vuln_db_path)
    intel_map = priority.build_intel_map(findings_table, vuln_db_path)

    ranked = priority.rank(findings_table, drift=records, intel=intel_map)
    order = priority.ordered_refs(ranked)
    fix_now_refs, still_open_refs = agent._split_by_band(ranked)

    # Read before save_scan_log below writes this run's own `scans` row, or
    # "previous" would resolve to the run we're in the middle of persisting.
    previous_scan = get_last_scan(scan_log_db_path, host_ip)
    save_scan_log(
        scan_log_db_path,
        host_ip,
        findings_table,
        scanner_status=scanner_status,
        drift=agent._resolved_status_overrides(records),
    )
    previous_scan_at = previous_scan["started_at"] if previous_scan else None

    fix_now_report = agent._attach_drift_markers(
        agent.run_report(report_llm, findings_table, fix_now_refs), findings_table
    )
    still_open_report = agent._attach_drift_markers(
        agent.run_report(report_llm, findings_table, still_open_refs), findings_table
    )
    resolved_report = agent._resolved_report(resolved_findings)

    report = {
        "drift_header": agent._drift_header(findings_table, resolved_findings, previous_scan_at),
        "fix_now": fix_now_report,
        "still_open": still_open_report,
        "resolved": resolved_report,
    }

    return {
        "report": report,
        "scanner_status": scanner_status,
        "findings_table": findings_table,
        "priority_order": order,
    }
