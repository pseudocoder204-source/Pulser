# SPDX-License-Identifier: GPL-2.0-only
import subprocess
import json
import os
import sys
import re
from typing import List, Dict, Any

from bin_resolver import resolve as _resolve_bin

#STAGE 1: AUTOMATED EXECUTION ENGINE

# Default hard timeout (seconds) for the trivy subprocess. A hung scan was a latent
# production hang with no prior bound — every worker must fail bounded, not hang.
DEFAULT_TRIVY_TIMEOUT = 300

def run_local_trivy_scan(timeout: int = DEFAULT_TRIVY_TIMEOUT) -> List[Dict[str, Any]]:
    """
    Kicks off a local open-source Trivy vulnerability audit (like a checklist) via the terminal
    and streams the results directly into system memory as JSON payload.
    """
    print(f"[*] Launching localized open-source Trivy vulnerability scanner...")

    command = [_resolve_bin("trivy"), "fs", "/", "--format", "json", "--quiet"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )

        parsed_json = json.loads(result.stdout)
        return parsed_json.get("Results", [])

    except FileNotFoundError:
        print("[!] Error: The 'trivy' binary is not installed on this host node.", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"[!] Trivy scan exceeded the {timeout}s timeout and was killed.", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"[!] Scanner failed during execution. Error details: {e.stderr}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Unexpected system crash: {e}", file=sys.stderr)
        return []
    
#STAGE 2: CLEAN TEXT TRUNCATION ENGINE
def clean_truncate_description(text_block: str, max_chars: int = 400) -> str:
    """
    Safely cuts long security text blocks down so they never end in 
    the middle of a word, keeping data clean for the LLM prompt
    """

    if not text_block or len(text_block) <= max_chars:
        return text_block

    raw_cut  = text_block[:max_chars]
    clean_cut = raw_cut.rsplit(' ', 1)[0]
    return f"{clean_cut}"

#STAGE 3: THE LLM CONDENSING AND ENRICHMENT LAYER

def build_llm_payload_from_trivy(trivy_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Takes raw Trivy outputs, calculates summary statistics, ranks threats,
    and isolates the top 10 worst bugs to protect LLM context windows.
    """
    priority_findings = []
    
    # Initialize metrics for overall risk scoring
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for target in trivy_results:
        vulnerabilities = target.get("Vulnerabilities", [])
        for v in vulnerabilities:
            severity = v.get("Severity", "UNKNOWN")
            
            # Aggregate total counts for our enriched metrics block
            if severity == "CRITICAL": critical_count += 1
            elif severity == "HIGH": high_count += 1
            elif severity == "MEDIUM": medium_count += 1
            elif severity == "LOW": low_count += 1

            # Noise Filter: Drop low and unknown vulnerabilities to save token space
            if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                entry = {
                    "cve_id": v.get("VulnerabilityID", "UNKNOWN-CVE"),
                    "package": v.get("PkgName", "Unknown Package"),
                    "installed_version": v.get("InstalledVersion", "N/A"),
                    "fixed_version": v.get("FixedVersion", "No Patch Available"),
                    "severity": severity,
                    "title": v.get("Title", "No title metadata available."),
                    # Apply our optimized text truncation method here
                    "description": clean_truncate_description(v.get("Description", ""))
                }
                priority_findings.append(entry)

    # Sort all findings mathematically so CRITICAL and HIGH issues float to the top
    severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    priority_findings.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)

    # Compile the final optimized structure
    return {
        "host_node": "production_target_host",
        "risk_summary": {
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "total_actionable": len(priority_findings)
        },
        # Slice the array down to protect token limitations
        "priority_findings": priority_findings[:10]
    }

def main():
    # 1. Run the local open-source scanner engine
    raw_scan_data = run_local_trivy_scan()

    if not raw_scan_data:
        print("[!] Pipeline aborted. No scan data captured.", file=sys.stderr)
        sys.exit(1)

    # 2. Package and condense the dataset for your LLM context window
    llm_ready_payload = build_llm_payload_from_trivy(raw_scan_data)

    # 3. Output clean, production-grade JSON
    print(json.dumps(llm_ready_payload, indent=2))


if __name__ == "__main__":
    main()