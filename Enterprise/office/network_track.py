#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier network track (Layer 3 building block).

Per Enterprise/Notes/office-audit-plan.txt, every fleet host gets the
always-on, zero-credential network scan regardless of whether a credentialed
transport is reachable. This module runs that scan for ONE host by calling
the exact same target-taking tool functions agent.py's own worker spine
calls (core/tools.py::_scan_network_no_sync, _scan_iot_defaults_no_sync,
scan_web.func) directly — not through agent.run_scan_phase(), which also
runs the LOCAL-ONLY workers (filesystem/host_audit/malware) that ignore
their `target` argument and always audit the machine running the code (see
core/tools.py::scan_filesystem/audit_host/get_last_malware_result docstrings).
Calling run_scan_phase(host_ip, token) per fleet host would silently rescan
the COORDINATOR's own filesystem/hardening/malware once per fleet host
instead of the remote host's — this module exists specifically to avoid
that bug by only ever invoking the three workers that actually take `target`
seriously.

Nothing in agent.py or core/tools.py is modified — this is pure reuse.
"""
from __future__ import annotations

import json
from typing import Any, Dict

from agent import _pick_web_scheme
from core import tools

__all__ = ["run_network_track"]


def _safe(name: str, fn) -> Any:
    """Run one probe; a single probe's failure must never take down the other
    two, same discipline as agent.py's own per-worker try/except."""
    try:
        return fn()
    except Exception as exc:
        return {"status": "error", "reason": f"{name}: {exc}"}


def run_network_track(host_ip: str) -> Dict[str, Any]:
    """Run the always-on, zero-credential network scan against `host_ip`.

    Returns {"network": ..., "iot_defaults": ..., "web": ...} — each value is
    the parsed JSON payload from the corresponding tool, or a
    {"status": "error", "reason": ...} dict if that one probe raised.
    """
    network = _safe("network", lambda: json.loads(tools._scan_network_no_sync(host_ip)))
    iot_defaults = _safe("iot_defaults", lambda: json.loads(tools._scan_iot_defaults_no_sync(host_ip)))

    results_so_far = {"network": network, "iot_defaults": iot_defaults}
    scheme = _pick_web_scheme(results_so_far, host_ip)
    web = _safe("web", lambda: json.loads(tools.scan_web.func(scheme)))

    return {"network": network, "iot_defaults": iot_defaults, "web": web}
