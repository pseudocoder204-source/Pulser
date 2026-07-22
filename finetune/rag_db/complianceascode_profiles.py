# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic ComplianceAsCode/content rule-selection filter.

Answers notes/RemediationRAGPlan.txt's open question "which rules are
home/SMB-appropriate" without asking an LLM to judge disruptiveness (that
was the whole problem with shipping raw STIG content -- see the plan doc's
Sources section). The basis, checked against a live clone via `gh api`
against ComplianceAsCode/content on 2026-07-19:

- Every product under `products/<product>/profiles/` ships zero or more
  `<tier>.profile` files (YAML). Some tiers (`cis_server_l1`, `stig`, ...)
  use an `extends:` chain and only list a *delta* on top of another
  profile -- resolving that properly needs the project's own build
  tooling, which is out of scope here. The `standard` and `basic` tiers,
  where present, were checked across debian12/debian13/ubuntu2204/rhel8/
  fedora/sle15/opensuse/ol9/almalinux9 and are flat, self-contained
  baselines (no `extends:`) -- exactly the "materially lighter" tier the
  plan doc already called out as the fix for STIG's disruptiveness.
- Selection basis: for each product, take the first profile found in
  `_PROFILE_TIER_PREFERENCE` order ("standard" before "basic"). Union the
  resulting rule IDs across every product. A product with **neither** tier
  present (confirmed today: rhel9, rhel10, ubuntu2404) contributes nothing
  and is reported, not guessed at -- e.g. RHEL9 has no "standard" profile
  upstream any more, and picking a stand-in (its "ospp" profile is the
  closest in spirit) would be a judgment call this script isn't positioned
  to make silently. Same principle as windows_audit_parser's `undetermined`
  findings: surface the gap, don't paper over it.
- `group@...` selection entries (rule-group references, not individual
  rule IDs) are not expanded -- resolving group membership means walking
  `group.yml` trees, which duplicates real ComplianceAsCode build logic.
  They're counted and reported so a human reviewer knows the allowlist is
  a conservative (rules may be missing, never spuriously added) approximation.
- `rule_id=value` entries (a selection that also sets a variable) count as
  a plain inclusion of `rule_id`; `!rule_id` entries are exclusions, applied
  after the product's own inclusions are collected.

This is intentionally *not* a per-distro filter at ingest time -- the union
across products is used because mark2 doesn't target one specific Linux
distro (Lynis runs distro-agnostically), so "in the lightest baseline of at
least one mainstream distro" is the inclusion bar, not "lightest baseline of
every distro" (which would be far too small) or "in any profile of any
product" (which would let a `stig`/`cis` tier back in through the union).
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import yaml

_PROFILE_TIER_PREFERENCE = ("standard", "basic")


@dataclass
class SelectionReport:
    allowed_rule_ids: Set[str] = field(default_factory=set)
    # rule_id -> list of {"product": ..., "tier": ...} contributors, for the
    # audit manifest a reviewer can check before trusting the filter.
    contributors: Dict[str, List[dict]] = field(default_factory=dict)
    products_used: List[Tuple[str, str]] = field(default_factory=list)   # (product, tier)
    products_skipped: List[str] = field(default_factory=list)           # no standard/basic tier
    group_selections_ignored: int = 0


def _rule_id_from_selection(item: str) -> str:
    return str(item).split("=", 1)[0].strip().strip('"').strip("'")


def list_products(repo_path: Path) -> List[str]:
    products_dir = repo_path / "products"
    if not products_dir.exists():
        return []
    return sorted(p.name for p in products_dir.iterdir() if p.is_dir())


def find_baseline_profile(repo_path: Path, product: str,
                           tier_preference: Tuple[str, ...] = _PROFILE_TIER_PREFERENCE) -> Optional[Tuple[Path, str]]:
    profiles_dir = repo_path / "products" / product / "profiles"
    if not profiles_dir.exists():
        return None
    for tier in tier_preference:
        candidate = profiles_dir / f"{tier}.profile"
        if candidate.exists():
            return candidate, tier
    return None


def parse_profile_selections(profile_path: Path) -> Tuple[Set[str], Set[str], int]:
    """Returns (included_rule_ids, excluded_rule_ids, group_selections_ignored)."""
    try:
        with profile_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as exc:
        print(f"[WARN] failed to parse {profile_path}: {exc}", file=sys.stderr)
        return set(), set(), 0

    selections = (data or {}).get("selections") or []
    included: Set[str] = set()
    excluded: Set[str] = set()
    group_ignored = 0
    for item in selections:
        item = str(item)
        if item.startswith("!"):
            excluded.add(_rule_id_from_selection(item[1:]))
        elif item.startswith("group@") or item.startswith("group:"):
            group_ignored += 1
        else:
            included.add(_rule_id_from_selection(item))
    return included, excluded, group_ignored


def collect_allowed_rule_ids(repo_path: Path,
                              tier_preference: Tuple[str, ...] = _PROFILE_TIER_PREFERENCE) -> SelectionReport:
    report = SelectionReport()
    for product in list_products(repo_path):
        found = find_baseline_profile(repo_path, product, tier_preference)
        if found is None:
            report.products_skipped.append(product)
            continue
        profile_path, tier = found
        included, excluded, group_ignored = parse_profile_selections(profile_path)
        report.group_selections_ignored += group_ignored
        report.products_used.append((product, tier))
        for rule_id in included - excluded:
            report.allowed_rule_ids.add(rule_id)
            report.contributors.setdefault(rule_id, []).append({"product": product, "tier": tier})
    return report
