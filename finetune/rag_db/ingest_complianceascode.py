# SPDX-License-Identifier: GPL-2.0-only
"""Ingest step for ComplianceAsCode/content rule groups, the active
hardening-benchmark corpus per notes/RemediationRAGPlan.txt "Sources"
(mSCP is a separate, deferred source -- not handled here).

**Linux only.** Verified against the live repo via `gh api` and a real
sparse clone on 2026-07-19: ComplianceAsCode/content has no `windows/`
directory and no Windows product under `products/` -- only Linux/Unix
distros (rhel, debian, ubuntu, sle, ...) plus a handful of applications
(firefox) and platforms (ocp4, eks). The plan doc's original "Covers Linux
and Windows" claim for this source was wrong and has been corrected; see
its "Open questions" for the resulting Windows-hardening-corpus gap.

Requires a local clone of https://github.com/ComplianceAsCode/content -- this
script does not clone or shallow-fetch the repo itself, since it's large and
cloning is a one-time setup step better done by hand. A sparse clone (only
`products/`, `linux_os/`, `ssg/` and `shared/` are actually read) is enough:

    git clone --depth 1 --filter=blob:none --sparse \\
        https://github.com/ComplianceAsCode/content.git
    cd content && git sparse-checkout set products linux_os ssg shared

`ssg/` and `shared/` (the latter holds `shared/macros/*.jinja`) are
ComplianceAsCode's *own* build-support package and Jinja macro library.
rule.yml/group.yml files are not plain YAML -- they're YAML with Jinja
macros/conditionals rendered in per-product context by the project's own
build tooling before anything treats them as a benchmark. This script
imports that `ssg` package directly off `--repo-path` (added to `sys.path`
at runtime, not pip-installed) and calls `ssg.yaml.open_and_expand`, the
same macro-expanding loader ComplianceAsCode's real build uses, instead of
reimplementing Jinja-aware parsing by hand. See `_import_ssg`.

Then:

    python3 -m finetune.rag_db.ingest_complianceascode --repo-path /path/to/content
    python3 -m finetune.rag_db.ingest_complianceascode --repo-path /path/to/content --limit 10 --dry-run

Rendering a rule.yml requires *some* product's context (Jinja conditionals
like `{{%- if product == 'rhel10' %}}` reference it), even though this corpus
is ingested product-agnostically -- see complianceascode_profiles.py's
"union across products" rationale. For each rule, the product is picked from
the profile-selection manifest's contributors (the first product whose
standard/basic profile actually selected that rule); rules with no
contributor on record (only possible with --no-profile-filter) fall back to
`--jinja-product` (default: the alphabetically-first product that
contributed to the selection). One `ssg.jinja`-loaded macro/env context is
built and cached per product, not per rule.

**Rule selection is filtered by default** -- see
finetune/rag_db/complianceascode_profiles.py for the deterministic basis
(union of each product's lightest available profile tier, "standard" before
"basic"; products with neither are skipped and reported, not guessed at).
Pass --no-profile-filter to ingest every rule regardless of profile
membership (useful for --dry-run exploration, not recommended for a real
ingest). A JSON manifest of exactly which rule IDs were selected and which
product/tier contributed each one is written next to --db-path so the
selection itself -- not just the resulting chunks -- can be reviewed.

One `sources` row per rule *group* (a directory with a group.yml, or its
directory name as a fallback), one `chunks` row per individual rule.yml
found under it -- this matches the "chunked passages" granularity in
notes/RemediationRAGPlan.txt's schema (a query should return one rule's
worth of grounding text, not a whole product guide).

Rule fix scripts (bash/shared.sh, ansible/shared.yml if present) are
appended to the chunk text as grounding context only, clearly labeled --
per the plan's Draft-step nuance, these are often multi-line and are never
copied verbatim into a catalog_step_commands row; a human distills them into
a single allowlisted command instead.
"""
import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import yaml

from finetune.rag_db.complianceascode_profiles import _PROFILE_TIER_PREFERENCE, collect_allowed_rule_ids
from finetune.rag_db.db import DEFAULT_DB_PATH, checksum_text, init_db, insert_chunk, upsert_source

# platform_key -> path (relative to --repo-path) to walk for rule.yml files.
# Verified against the live repo (see module docstring) -- linux_os/guide is
# the only content tree that exists today.
_PLATFORM_ROOTS = {
    "linux": "linux_os/guide",
}

_LICENSE = "bsd_3_clause"
_PUBLISHER = "ComplianceAsCode"
_FIX_SNIPPET_MAX_CHARS = 2000

#used for version matching
def _git_short_sha(repo_path: Path) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


_ssg_modules = None  # memoized (ssg.yaml, ssg.jinja, ssg.products), see _import_ssg


def _import_ssg(repo_path: Path):
    """Imports ComplianceAsCode's own `ssg` build-support package straight off
    --repo-path (put on sys.path here, not pip-installed -- it isn't published
    to PyPI). rule.yml/group.yml are Jinja-templated YAML; this is upstream's
    own macro-expanding loader for them, not a reimplementation."""
    global _ssg_modules
    if _ssg_modules is not None:
        return _ssg_modules

    repo_str = str(repo_path.resolve())
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)
    try:
        import ssg.jinja as ssg_jinja
        import ssg.products as ssg_products
        import ssg.yaml as ssg_yaml
    except ImportError as exc:
        raise ImportError(
            f"could not import the ComplianceAsCode 'ssg' package from {repo_path} -- "
            "sparse-checkout must include the 'ssg' and 'shared' directories "
            "(see module docstring for the git sparse-checkout command)"
        ) from exc

    _ssg_modules = (ssg_yaml, ssg_jinja, ssg_products)
    return _ssg_modules


def _build_env_yaml(repo_path: Path, product: str) -> Optional[dict]:
    """Builds the Jinja substitution context Rule.yml/group.yml conditionals
    (`{{%- if product == ... %}}`, `{{{ full_name }}}`, ...) expect, from one
    product's product.yml plus the shared macro library. Not build_config.yml.in
    -- that's an unrendered CMake template (`@VAR@` placeholders) outside a real
    CMake build, not valid YAML on its own; `cmake_build_type` defaults to
    "Release" instead, matching every real packaged build."""
    ssg_yaml, ssg_jinja, ssg_products = _import_ssg(repo_path)
    product_yaml_path = repo_path / "products" / product / "product.yml"
    if not product_yaml_path.exists():
        print(f"[WARN] no product.yml for product={product!r} at {product_yaml_path}", file=sys.stderr)
        return None
    try:
        product_obj = ssg_products.load_product_yaml(str(product_yaml_path))
    except (OSError, yaml.YAMLError) as exc:
        print(f"[WARN] failed to load {product_yaml_path}: {exc}", file=sys.stderr)
        return None

    env_yaml = dict(product_obj)
    env_yaml.setdefault("cmake_build_type", "Release")
    return ssg_jinja.load_macros(env_yaml)


def _load_ssg_yaml(path: Path, repo_path: Path, product: str,
                    env_cache: Dict[str, Optional[dict]]) -> Optional[dict]:
    """Loads a rule.yml or group.yml via ssg.yaml.open_and_expand, rendering
    Jinja in `product`'s context. env_cache memoizes the built context per
    product across the whole ingest run (rebuilding per rule would recompile
    every macro file on each call)."""
    ssg_yaml, _, _ = _import_ssg(repo_path)
    if product not in env_cache:
        env_cache[product] = _build_env_yaml(repo_path, product)
    env_yaml = env_cache[product]
    if env_yaml is None:
        return None

    try:
        data = ssg_yaml.open_and_expand(str(path), env_yaml)
    except ssg_yaml.DocumentationNotComplete:
        return None
    except SystemExit:
        # open_and_expand sys.exit(1)s on a post-expansion YAML ScannerError
        # (a Jinja substitution mangled indentation) instead of raising --
        # upstream's own error path (see ssg/yaml.py), not a reason to abort
        # the whole ingest run.
        print(f"[WARN] ssg Jinja/YAML expansion failed for {path} (product={product})", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[WARN] failed to parse {path} via ssg (product={product}): {exc}", file=sys.stderr)
        return None

    return data if isinstance(data, dict) else None


def _pick_product(rule_id: str, contributors: Dict[str, List[dict]], default_product: str) -> str:
    contribs = contributors.get(rule_id)
    if contribs:
        return contribs[0]["product"]
    return default_product


def _nearest_group_dir(rule_yml_path: Path, platform_root: Path) -> Path:
    """Walks up from a rule.yml's parent dir looking for a sibling group.yml.
    Falls back to the immediate parent directory if none is found before
    hitting platform_root."""
    d = rule_yml_path.parent
    while d != platform_root and platform_root in d.parents:
        if (d / "group.yml").exists():
            return d
        d = d.parent
    return rule_yml_path.parent


def _group_title(group_dir: Path, repo_path: Path, product: str,
                  env_cache: Dict[str, Optional[dict]]) -> str:
    group_yml = group_dir / "group.yml"
    if group_yml.exists():
        data = _load_ssg_yaml(group_yml, repo_path, product, env_cache)
        if data and data.get("title"):
            return str(data["title"])
    return group_dir.name


def _read_fix_snippet(rule_dir: Path) -> Optional[str]:
    for candidate in ("bash/shared.sh", "ansible/shared.yml"):
        p = rule_dir / candidate
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if text:
                truncated = text[:_FIX_SNIPPET_MAX_CHARS]
                suffix = " ...[truncated]" if len(text) > _FIX_SNIPPET_MAX_CHARS else ""
                return f"[upstream {candidate} -- grounding only, not a catalog_step_commands source verbatim]\n{truncated}{suffix}"
    return None


def _rule_chunk_text(rule_id: str, rule_data: dict, fix_snippet: Optional[str]) -> str:
    parts = [f"Rule: {rule_id}"]
    if rule_data.get("title"):
        parts.append(f"Title: {rule_data['title']}")
    if rule_data.get("description"):
        parts.append(f"Description: {rule_data['description']}")
    if rule_data.get("rationale"):
        parts.append(f"Rationale: {rule_data['rationale']}")
    if rule_data.get("severity"):
        parts.append(f"Severity: {rule_data['severity']}")
    references = rule_data.get("references")
    if references:
        parts.append(f"References: {references}")
    if fix_snippet:
        parts.append(fix_snippet)
    return "\n\n".join(str(p) for p in parts)


# Conservative headroom under nomic-embed-text's 2048-token architecture cap
# (see embed_chunks.py) -- the symbol-dense bash/Jinja fix snippets tokenize
# far worse than prose (lots of underscores, quotes, parens), so this is
# chars, not tokens, and picked well below the point that failed embedding
# (a 4997-char audit-rule chunk 500'd with "input length exceeds the context
# length"), not derived from an exact token count.
_EMBED_CHUNK_MAX_CHARS = 1600


def _pack_atoms(atoms: List[str], max_chars: int) -> List[str]:
    """Greedily packs atoms (metadata fields / fix-snippet lines) into chunks
    up to max_chars, joined by blank lines. An atom that alone exceeds
    max_chars (e.g. a long Description/Rationale field with no internal
    newlines to split on) is hard char-sliced -- ugly for a human reading
    that one slice, but this text is grounding-only for RAG retrieval, not
    the source of catalog_step_commands, so an occasional mid-sentence cut is
    an acceptable tradeoff against a chunk the embedding model rejects
    outright."""
    packed: List[str] = []
    buf: List[str] = []
    buf_len = 0
    for atom in atoms:
        while len(atom) > max_chars:
            if buf:
                packed.append("\n\n".join(buf))
                buf, buf_len = [], 0
            packed.append(atom[:max_chars])
            atom = atom[max_chars:]
        if not atom:
            continue
        added = len(atom) + (2 if buf else 0)
        if buf and buf_len + added > max_chars:
            packed.append("\n\n".join(buf))
            buf, buf_len = [atom], len(atom)
        else:
            buf.append(atom)
            buf_len += added
    if buf:
        packed.append("\n\n".join(buf))
    return packed


# Headroom reserved on continuation chunks for the short "(continued)" prefix
# added below -- keeps every packed piece, prefix included, under max_chars.
_CONTINUATION_PREFIX_BUDGET = 80


def _rule_chunks(rule_id: str, rule_data: dict, fix_snippet: Optional[str],
                  max_chars: int = _EMBED_CHUNK_MAX_CHARS) -> List[tuple]:
    """Returns [(section_ref, text), ...] for one rule. A single chunk in the
    common case; when the combined metadata + fix snippet text exceeds
    max_chars (either the long multi-branch audit-rule fix scripts, or --
    less commonly -- a long Description/Rationale field), it's split across
    multiple continuation chunks, each carrying a short header so it's still
    self-contained for retrieval -- splitting a >2048-token chunk was the
    only way to get it embedded at all with nomic-embed-text's fixed context
    length."""
    full_text = _rule_chunk_text(rule_id, rule_data, fix_snippet)
    if len(full_text) <= max_chars:
        return [(rule_id, full_text)]

    metadata_parts = [f"Rule: {rule_id}"]
    if rule_data.get("title"):
        metadata_parts.append(f"Title: {rule_data['title']}")
    if rule_data.get("description"):
        metadata_parts.append(f"Description: {rule_data['description']}")
    if rule_data.get("rationale"):
        metadata_parts.append(f"Rationale: {rule_data['rationale']}")
    if rule_data.get("severity"):
        metadata_parts.append(f"Severity: {rule_data['severity']}")
    references = rule_data.get("references")
    if references:
        metadata_parts.append(f"References: {references}")

    atoms = [str(p) for p in metadata_parts] + (fix_snippet.split("\n") if fix_snippet else [])
    budget = max_chars - _CONTINUATION_PREFIX_BUDGET
    packed = _pack_atoms(atoms, budget)

    chunks: List[tuple] = []
    for i, text in enumerate(packed, start=1):
        if i == 1:
            chunks.append((rule_id, text))
        else:
            chunks.append((f"{rule_id}#{i}", f"Rule: {rule_id} (continued)\n\n{text}"))
    return chunks


def find_rule_files(platform_root: Path) -> List[Path]:
    if not platform_root.exists():
        return []
    return sorted(platform_root.rglob("rule.yml"))


def ingest_platform(conn, repo_path: Path, platform_key: str, relative_root: str,
                     *, limit: Optional[int], dry_run: bool, doc_version: Optional[str],
                     allowed_rule_ids: Optional[Set[str]], contributors: Dict[str, List[dict]],
                     default_product: str, env_cache: Dict[str, Optional[dict]]) -> int:
    platform_root = repo_path / relative_root
    rule_files = find_rule_files(platform_root)
    if not rule_files:
        print(f"[WARN] no rule.yml files found under {platform_root} for platform={platform_key!r}",
              file=sys.stderr)
        return 0

    if allowed_rule_ids is not None:
        before = len(rule_files)
        rule_files = [f for f in rule_files if f.parent.name in allowed_rule_ids]
        print(f"[FILTER] {platform_key}: {before} rule.yml file(s) found, "
              f"{len(rule_files)} kept after profile-selection filter")

    groups: Dict[Path, List[Path]] = defaultdict(list)
    for rule_file in rule_files:
        groups[_nearest_group_dir(rule_file, platform_root)].append(rule_file)

    group_items = sorted(groups.items())
    if limit:
        group_items = group_items[:limit]

    total_chunks = 0
    for group_dir, rules_in_group in group_items:
        group_product = _pick_product(rules_in_group[0].parent.name, contributors, default_product)
        title = _group_title(group_dir, repo_path, group_product, env_cache)
        chunk_texts = []
        for rule_file in rules_in_group:
            rule_id = rule_file.parent.name
            product = _pick_product(rule_id, contributors, default_product)
            rule_data = _load_ssg_yaml(rule_file, repo_path, product, env_cache)
            if rule_data is None:
                continue
            fix_snippet = _read_fix_snippet(rule_file.parent)
            chunk_texts.extend(_rule_chunks(rule_id, rule_data, fix_snippet))

        if not chunk_texts:
            continue

        combined_checksum = checksum_text("\n---\n".join(t for _, t in chunk_texts))

        if dry_run:
            print(f"[DRY-RUN] {platform_key}/{group_dir.relative_to(repo_path)} ({title!r}): "
                  f"{len(chunk_texts)} rule chunk(s)")
            total_chunks += len(chunk_texts)
            continue

        source_id, changed = upsert_source(
            conn,
            corpus="complianceascode",
            title=f"{title} ({group_dir.relative_to(repo_path)})",
            publisher=_PUBLISHER,
            url=f"https://github.com/ComplianceAsCode/content/tree/master/{group_dir.relative_to(repo_path)}",
            doc_version=doc_version,
            license=_LICENSE,
            platform=platform_key,
            checksum=combined_checksum,
        )
        if not changed:
            continue

        for rule_id, text in chunk_texts:
            insert_chunk(
                conn,
                source_id=source_id,
                section_ref=rule_id,
                text=text,
                finding_class_hint=None,  # left for the Draft step / manual tagging
                platform=platform_key,
            )
        conn.commit()
        total_chunks += len(chunk_texts)
        print(f"[OK] {platform_key}/{group_dir.relative_to(repo_path)} ({title!r}): "
              f"{len(chunk_texts)} chunk(s) written (source_id={source_id})")

    return total_chunks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-path", type=Path, required=True,
                         help="local clone of github.com/ComplianceAsCode/content")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--platform", choices=sorted(_PLATFORM_ROOTS), default=None,
                         help="only ingest one platform (default: all in _PLATFORM_ROOTS)")
    parser.add_argument("--limit", type=int, default=None,
                         help="only ingest the first N rule groups per platform (for review)")
    parser.add_argument("--dry-run", action="store_true", help="walk + chunk but don't write to the DB")
    parser.add_argument("--no-profile-filter", action="store_true",
                         help="ingest every rule regardless of profile membership "
                              "(default: filtered to the standard/basic tier union, "
                              "see complianceascode_profiles.py)")
    parser.add_argument("--profile-tiers", default=",".join(_PROFILE_TIER_PREFERENCE),
                         help=f"comma-separated tier preference order (default: {','.join(_PROFILE_TIER_PREFERENCE)})")
    parser.add_argument("--selection-manifest", type=Path, default=None,
                         help="where to write the rule-selection audit JSON "
                              "(default: <db-path>.selection_manifest.json)")
    parser.add_argument("--jinja-product", default=None,
                         help="product whose product.yml provides the Jinja rendering context "
                              "for a rule.yml/group.yml with no profile-selection contributor on "
                              "record (only reachable with --no-profile-filter; every filtered-in "
                              "rule has a contributor already). Default: the alphabetically-first "
                              "product that contributed to the selection.")
    args = parser.parse_args()

    if not args.repo_path.exists():
        print(f"[FAIL] --repo-path {args.repo_path} does not exist", file=sys.stderr)
        return 1

    try:
        _import_ssg(args.repo_path)
    except ImportError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    doc_version = _git_short_sha(args.repo_path)
    doc_version_str = f"ComplianceAsCode content @{doc_version}" if doc_version else None

    # Computed unconditionally (cheap -- just parses *.profile files): rule
    # rendering needs a per-rule product pick even when --no-profile-filter
    # leaves every rule in, see module docstring.
    tier_preference = tuple(t.strip() for t in args.profile_tiers.split(",") if t.strip())
    report = collect_allowed_rule_ids(args.repo_path, tier_preference)

    allowed_rule_ids: Optional[Set[str]] = None
    if not args.no_profile_filter:
        allowed_rule_ids = report.allowed_rule_ids
        print(f"[SELECT] {len(report.products_used)} product(s) contributed "
              f"({','.join(t for _, t in report.products_used)} tiers used), "
              f"{len(report.products_skipped)} skipped (no {'/'.join(tier_preference)} tier): "
              f"{', '.join(report.products_skipped) or 'none'}")
        print(f"[SELECT] {len(allowed_rule_ids)} distinct rule ID(s) allowed; "
              f"{report.group_selections_ignored} group@ selection(s) ignored (not expanded)")

        manifest_path = args.selection_manifest or args.db_path.with_suffix(".selection_manifest.json")
        manifest = {
            "tier_preference": list(tier_preference),
            "products_used": [{"product": p, "tier": t} for p, t in report.products_used],
            "products_skipped": report.products_skipped,
            "group_selections_ignored": report.group_selections_ignored,
            "allowed_rule_ids": {rule_id: contribs for rule_id, contribs in sorted(report.contributors.items())},
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print(f"[SELECT] selection manifest written to {manifest_path}")

    if args.jinja_product:
        default_product = args.jinja_product
    elif report.products_used:
        default_product = sorted(p for p, _ in report.products_used)[0]
    else:
        print("[FAIL] no product contributed a standard/basic profile and no --jinja-product "
              "was given -- nothing to render rule.yml Jinja context with", file=sys.stderr)
        return 1
    print(f"[SELECT] default Jinja rendering product (for rules with no contributor on record): "
          f"{default_product!r}")

    platforms = [args.platform] if args.platform else sorted(_PLATFORM_ROOTS)
    conn = None if args.dry_run else init_db(args.db_path)
    env_cache: Dict[str, Optional[dict]] = {}

    total = 0
    for platform_key in platforms:
        total += ingest_platform(
            conn, args.repo_path, platform_key, _PLATFORM_ROOTS[platform_key],
            limit=args.limit, dry_run=args.dry_run, doc_version=doc_version_str,
            allowed_rule_ids=allowed_rule_ids, contributors=report.contributors,
            default_product=default_product, env_cache=env_cache,
        )

    if conn is not None:
        conn.close()

    print(f"\n{total} chunk(s) processed across {len(platforms)} platform(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
