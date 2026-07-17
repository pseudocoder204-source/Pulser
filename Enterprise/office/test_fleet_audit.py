# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the pure, no-network functions added for office-audit-plan.txt
Layers 3-4: host_report.build_host_results and fleet_audit.build_coverage_matrix /
summarize_fleet. No SSH/WinRM/nmap involved -- these operate on plain dicts.

Kept inside Enterprise/ (not tests/) per office-audit-plan.txt's containment rule
(line 16: build everything related to this plan inside Enterprise/).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Enterprise.office.fleet_audit import build_coverage_matrix, summarize_fleet
from Enterprise.office.host_report import build_host_results


class BuildHostResultsTests(unittest.TestCase):
    def test_with_credentialed_result_passes_hardening_and_malware_through(self):
        network_result = {"network": {"status": "ok"}, "iot_defaults": {"status": "ok"}, "web": {"status": "ok"}}
        credentialed_result = {
            "hardening": {"priority_findings": [{"test_id": "UAC-DISABLED"}]},
            "malware": {"priority_findings": []},
        }
        results = build_host_results(network_result, credentialed_result)
        self.assertEqual(results["host_audit"], credentialed_result["hardening"])
        self.assertEqual(results["malware"], credentialed_result["malware"])
        self.assertEqual(results["network"], network_result["network"])

    def test_without_transport_marks_hardening_and_malware_not_assessed_never_clean(self):
        network_result = {"network": {"status": "ok"}, "iot_defaults": {"status": "ok"}, "web": {"status": "ok"}}
        results = build_host_results(network_result, credentialed_result=None)
        self.assertEqual(results["host_audit"]["status"], "not_assessed")
        self.assertEqual(results["malware"]["status"], "not_assessed")

    def test_filesystem_is_always_not_assessed_no_remote_path(self):
        results = build_host_results({"network": {}, "iot_defaults": {}, "web": {}}, credentialed_result=None)
        self.assertEqual(results["filesystem"]["status"], "not_assessed")


class BuildCoverageMatrixTests(unittest.TestCase):
    def test_ok_host_reports_its_own_scanner_status(self):
        hosts = {
            "10.0.0.5": {
                "status": "ok",
                "scanner_status": {"network": "ok", "host_audit": "not_assessed", "malware": "not_assessed"},
            }
        }
        matrix = build_coverage_matrix(hosts)
        self.assertEqual(matrix["10.0.0.5"]["host_audit"], "not_assessed")
        self.assertEqual(matrix["10.0.0.5"]["network"], "ok")

    def test_errored_host_never_reported_as_clean(self):
        hosts = {"10.0.0.9": {"status": "error", "reason": "unreachable"}}
        matrix = build_coverage_matrix(hosts)
        self.assertEqual(matrix["10.0.0.9"], {"_sweep": "error"})


class SummarizeFleetTests(unittest.TestCase):
    def test_worst_risk_is_the_max_across_assessed_hosts(self):
        hosts = {
            "10.0.0.1": {"status": "ok", "report": {"fix_now": {"overall_risk": "low"}}},
            "10.0.0.2": {"status": "ok", "report": {"fix_now": {"overall_risk": "critical"}}},
            "10.0.0.3": {"status": "error", "reason": "timeout"},
        }
        summary = summarize_fleet(hosts)
        self.assertEqual(summary["total_hosts"], 3)
        self.assertEqual(summary["assessed_hosts"], 2)
        self.assertEqual(summary["errored_hosts"], 1)
        self.assertEqual(summary["worst_overall_risk"], "critical")
        self.assertIn("10.0.0.2", summary["hosts_by_risk"]["critical"])

    def test_all_hosts_errored_reports_unknown_worst_risk(self):
        hosts = {"10.0.0.1": {"status": "error", "reason": "unreachable"}}
        summary = summarize_fleet(hosts)
        self.assertEqual(summary["worst_overall_risk"], "unknown")


if __name__ == "__main__":
    unittest.main()
