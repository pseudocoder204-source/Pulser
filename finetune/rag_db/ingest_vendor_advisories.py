# SPDX-License-Identifier: GPL-2.0-only
"""Ingest step for vendor advisories / distro patch-notes pages
(notes/RemediationRAGPlan.txt "Ingest" — the vendor-advisory half; see
ingest_complianceascode.py for the hardening-benchmark half).

Fetches each URL in vendor_advisory_sources.VENDOR_ADVISORY_SOURCES, strips
HTML down to text, chunks it into paragraphs, and writes sources/chunks rows.
Re-running is a no-op for any page whose content hasn't changed since the
last run (db.upsert_source dedups on a content checksum).

Run standalone:

    python3 -m finetune.rag_db.ingest_vendor_advisories
    python3 -m finetune.rag_db.ingest_vendor_advisories --db-path /tmp/test.db --limit 3

Network access required (plain HTTP GET per source, no auth, no API key).
Any source that fails to fetch -- even through the Wayback Machine fallback
below -- is reported and skipped; one dead URL doesn't abort the whole run.

**Wayback Machine fallback**: some publishers (confirmed for cisa.gov)
403 every direct fetch regardless of User-Agent -- edge-level bot blocking,
not a UA check (verified 2026-07-20: a full browser UA string still 403s).
When the direct fetch fails, `fetch_source` asks archive.org's
`/wayback/available` API for the closest snapshot of the same URL and
retries against that -- same publisher's own text, just mirrored, so the
license tier in `vendor_advisory_sources.py` still applies unchanged. The
snapshot's timestamp is recorded in `sources.doc_version` so it's visible in
the DB which rows came from a mirror rather than a live fetch.
"""
import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import requests

from finetune.rag_db.chunking import merge_short_paragraphs, split_paragraphs
from finetune.rag_db.db import DEFAULT_DB_PATH, checksum_text, get_connection, init_db, insert_chunk, upsert_source
from finetune.rag_db.html_text import html_to_text
from finetune.rag_db.vendor_advisory_sources import VENDOR_ADVISORY_SOURCES

_USER_AGENT = "mark2-rag-ingest/0.1 (+build-time remediation catalog authoring tool)"
_TIMEOUT_S = 20
_WAYBACK_AVAILABLE_API = "https://archive.org/wayback/available"


def _wayback_snapshot(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (snapshot_url, timestamp) for the closest archived snapshot of
    `url`, or (None, None) if archive.org has none / the lookup itself fails
    -- callers treat that as "no fallback available", not an error."""
    try:
        resp = requests.get(_WAYBACK_AVAILABLE_API, params={"url": url}, timeout=_TIMEOUT_S)
        resp.raise_for_status()
        snap = resp.json().get("archived_snapshots", {}).get("closest")
    except (requests.RequestException, ValueError):
        return None, None
    if not snap or not snap.get("available"):
        return None, None
    return snap["url"], snap.get("timestamp")


def fetch_source(url: str) -> Tuple[str, Optional[str]]:
    """Returns (html, doc_version_note). doc_version_note is None for a
    direct fetch, or a note describing the Wayback Machine snapshot used
    when the direct fetch failed."""
    try:
        resp = requests.get(url, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT_S)
        resp.raise_for_status()
        return resp.text, None
    except requests.RequestException as direct_exc:
        snapshot_url, timestamp = _wayback_snapshot(url)
        if not snapshot_url:
            raise direct_exc
        print(f"[FALLBACK] {url}: direct fetch failed ({direct_exc}); "
              f"using Wayback Machine snapshot {snapshot_url}", file=sys.stderr)
        resp = requests.get(snapshot_url, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT_S)
        resp.raise_for_status()
        return resp.text, f"via web.archive.org snapshot {timestamp}"


def ingest_one(conn, spec, *, dry_run: bool = False) -> int:
    """Returns the number of chunks written (0 if skipped as unchanged)."""
    try:
        html, doc_version = fetch_source(spec["url"])
    except requests.RequestException as exc:
        print(f"[SKIP] {spec['title']!r} ({spec['url']}): fetch failed -- {exc}", file=sys.stderr)
        return 0

    text = html_to_text(html)
    checksum = checksum_text(text)

    if dry_run:
        paragraphs = merge_short_paragraphs(split_paragraphs(text))
        print(f"[DRY-RUN] {spec['title']!r}: {len(text)} chars -> {len(paragraphs)} chunk(s)"
              + (f" ({doc_version})" if doc_version else ""))
        return len(paragraphs)

    source_id, changed = upsert_source(
        conn,
        corpus=spec["corpus"],
        title=spec["title"],
        publisher=spec["publisher"],
        url=spec["url"],
        doc_version=doc_version,
        license=spec["license"],
        platform=spec["platform"],
        checksum=checksum,
    )
    if not changed:
        print(f"[SKIP] {spec['title']!r}: unchanged since last ingest")
        return 0

    paragraphs = merge_short_paragraphs(split_paragraphs(text))
    for i, para in enumerate(paragraphs):
        insert_chunk(
            conn,
            source_id=source_id,
            section_ref=f"paragraph_{i}",
            text=para,
            finding_class_hint=spec["finding_class_hint"],
            platform=spec["platform"],
        )
    conn.commit()
    print(f"[OK] {spec['title']!r}: {len(paragraphs)} chunk(s) written (source_id={source_id})")
    return len(paragraphs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--limit", type=int, default=None, help="only ingest the first N sources (for review)")
    parser.add_argument("--dry-run", action="store_true", help="fetch + chunk but don't write to the DB")
    args = parser.parse_args()

    sources = VENDOR_ADVISORY_SOURCES[: args.limit] if args.limit else VENDOR_ADVISORY_SOURCES

    conn = None if args.dry_run else init_db(args.db_path)
    total_chunks = 0
    for spec in sources:
        total_chunks += ingest_one(conn, spec, dry_run=args.dry_run)
    if conn is not None:
        conn.close()

    print(f"\n{len(sources)} source(s) processed, {total_chunks} chunk(s) written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
