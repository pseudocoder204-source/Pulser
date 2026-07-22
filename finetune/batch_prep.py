# SPDX-License-Identifier: GPL-2.0-only
"""Batch prep for Claude Code labeling sessions (notes/UpgradeTuning.txt Step 4).

Selects trainset.db rows with status='pending', and for each writes a blanked
report skeleton alongside the row's ordered_facts — the skeleton mechanically
copies every invariant the validators check (affected strings, severity tiers,
critical/high/medium partition, reference URLs) while leaving every prose field
("title", "what_it_means", "why_it_matters", "how_to_fix", "summary", and each
good_news bullet) empty, so a labeling session can only fill in fresh prose —
it can't accidentally break structure doing it.

Usage:
    python3 finetune/batch_prep.py                 # prep all pending rows, 25/batch
    python3 finetune/batch_prep.py --limit 20       # pilot batch (Verification §1)
    python3 finetune/batch_prep.py --batch-size 25 --out-dir finetune/batches

Resumable: rows already present in an existing finetune/batches/batch_*.json
(labeled or not) are skipped, so re-running after a labeling session only
prepares the rows that haven't been batched yet.
"""
import argparse
import glob
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.priority import overall_risk_tier

_DB_PATH = "trainset.db"
_OUT_DIR = "finetune/batches"
_BATCH_SIZE = 25
_LABELING_MD = "finetune/LABELING.md"
_VULN_DB_PATH = "vulnerability_cache.db"


def _skeleton_refs(f: dict) -> list:
    refs = [r for r in (f.get("remediation_refs") or []) if isinstance(r, str) and r.startswith("http")]
    for r in (f.get("fix_facts") or {}).get("references", []) or []:
        if isinstance(r, str) and r.startswith("http") and r not in refs:
            refs.append(r)
    return refs


def build_skeleton(ordered_facts: list, vuln_db_path: str = _VULN_DB_PATH) -> dict:
    """Blanked report shape for one row — see module docstring for the invariant
    it guarantees. Mirrors the agent.py _deterministic_report partition: 'low'
    findings become good_news stubs, everything else becomes a findings stub.
    `overall_risk` uses the same escalation-aware `priority.overall_risk_tier`
    the deterministic report now uses, rather than a bare severity ceiling, so
    the training labels match what the real fallback (and thus the model) is
    held to."""
    findings = []
    good_news = []

    for f in ordered_facts:
        sev = f.get("severity", "low")
        if sev == "low":
            good_news.append("")
            continue
        findings.append({
            "title": "",
            "severity": sev,
            "what_it_means": "",
            "why_it_matters": "",
            "how_to_fix": "",
            "affected": f.get("affected"),
            "references": _skeleton_refs(f),
        })

    return {
        "overall_risk": overall_risk_tier(ordered_facts, db_path=vuln_db_path),
        "summary": "",
        "findings": findings,
        "good_news": good_news,
    }


def _already_batched_ids(out_dir: str) -> set:
    ids = set()
    for path in glob.glob(os.path.join(out_dir, "batch_*.json")):
        try:
            with open(path) as fh:
                rows = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        for row in rows:
            ids.add(row["id"])
    return ids


def _next_batch_num(out_dir: str) -> int:
    nums = []
    for path in glob.glob(os.path.join(out_dir, "batch_*.json")):
        stem = os.path.splitext(os.path.basename(path))[0]  # batch_007
        try:
            nums.append(int(stem.split("_")[1]))
        except (IndexError, ValueError):
            continue
    return max(nums, default=0) + 1


_LABELING_MD_CONTENT = """# Labeling instructions for finetune/batches/batch_NNN.json

Each row is `{"id": ..., "ordered_facts": [...], "skeleton": {...}}`. Fill in the
blanked `skeleton` to produce a finished report, and write the result to
`batch_NNN.labeled.json` (same shape as `batch_NNN.json`, with `skeleton` replaced
by `label`).

## The contract (same one the report LLM is held to in production)

You are a friendly, knowledgeable security diagnostician helping everyday home users
and small business owners understand the security health of their devices and
network. Your audience has NO technical background — always use plain, everyday
language.

Each finding in `ordered_facts` already has an `affected` string and a `severity`
tier computed for you — never change severity, never invent a fact not present in
`ordered_facts`.

Some findings carry a `fix_facts` object — pre-verified remediation facts (a fix
summary, ordered steps, and sometimes a `fixed_version` or `solution`) already
grounded in that finding's own data. When `fix_facts` is present, build
`how_to_fix` from it: turn its `steps` into your numbered steps, and if it has a
`fixed_version` your steps must state that version. When `fix_facts` is null,
give only safe generic advice (update the software / disable the feature /
restrict network access) and say plainly that a specific fix wasn't identified.

## What to write

- `title`, `what_it_means`, `why_it_matters`: rewrite fresh from that finding's
  `ordered_facts` fields — specific to *this* finding, not generic boilerplate.
- `how_to_fix`: numbered steps (`1. ... 2. ...`) rewritten from `fix_facts` per
  the rule above. Home-user voice: "change your router's admin password", not
  "rotate default credentials".
- Each empty `good_news` string: one reassuring sentence for that low-severity item.
- `summary`: 2-3 plain sentences on the overall situation.
- Leave `severity`, `affected`, and `references` exactly as the skeleton has them —
  those are already correct and validated mechanically.

## Hard rules (validators reject on these)

- Never write a CVE ID, a CVSS number/score, or a CPE string anywhere in the
  report. Translate everything to everyday language instead.
- **URLs go only in `references`, never inside `how_to_fix` prose** — `fix_facts`
  can carry patch URLs whose paths embed CVE IDs, and copying one into
  `how_to_fix` trips the CVE-leak check.
- Don't change `severity` or `affected` from what the skeleton already has.
- Don't add or drop findings/good_news entries — the skeleton's partition
  (critical/high/medium → findings, low → good_news) is already correct.
- Output must be valid JSON, same shape as the skeleton.

## Workflow

"label finetune/batches/batch_007.json per finetune/LABELING.md" → fill every
row's skeleton into a finished `label`, write `batch_007.labeled.json`. Spot-check
~1 in 5 batches by hand before import (read 3 random labels) — the human-voice QA
pass. Then `python3 finetune/batch_import.py finetune/batches/batch_007.labeled.json`.
"""


def _write_labeling_md(path: str, force: bool) -> None:
    if os.path.exists(path) and not force:
        return
    with open(path, "w") as fh:
        fh.write(_LABELING_MD_CONTENT)
    print(f"wrote {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=_DB_PATH)
    ap.add_argument("--out-dir", default=_OUT_DIR)
    ap.add_argument("--batch-size", type=int, default=_BATCH_SIZE)
    ap.add_argument("--vuln-db", default=_VULN_DB_PATH, help="KEV/EPSS cache used for overall_risk escalation")
    ap.add_argument("--limit", type=int, default=None, help="cap total rows prepped (pilot batches)")
    ap.add_argument("--force-labeling-md", action="store_true", help="overwrite an existing LABELING.md")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    _write_labeling_md(_LABELING_MD, args.force_labeling_md)

    conn = sqlite3.connect(args.db)
    rows = conn.execute(
        "SELECT id, ordered_facts FROM examples "
        "WHERE status = 'pending' AND source != 'synth_triage' ORDER BY id"
    ).fetchall()

    already = _already_batched_ids(args.out_dir)
    pending = [(rid, of) for rid, of in rows if rid not in already]
    if args.limit is not None:
        pending = pending[: args.limit]

    if not pending:
        print("no new pending rows to batch")
        return

    batch_num = _next_batch_num(args.out_dir)
    written_rows = 0
    written_batches = 0
    for start in range(0, len(pending), args.batch_size):
        chunk = pending[start : start + args.batch_size]
        batch = []
        for rid, of in chunk:
            ordered_facts = json.loads(of)
            batch.append({
                "id": rid,
                "ordered_facts": ordered_facts,
                "skeleton": build_skeleton(ordered_facts, vuln_db_path=args.vuln_db),
            })
        out_path = os.path.join(args.out_dir, f"batch_{batch_num:03d}.json")
        with open(out_path, "w") as fh:
            json.dump(batch, fh, indent=2)
        print(f"wrote {out_path} ({len(batch)} rows)")
        written_rows += len(batch)
        written_batches += 1
        batch_num += 1

    print(f"\n{written_batches} batch file(s), {written_rows} row(s) prepped "
          f"({len(already)} already batched and skipped)")


if __name__ == "__main__":
    main()
