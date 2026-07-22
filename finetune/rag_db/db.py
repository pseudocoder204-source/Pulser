# SPDX-License-Identifier: GPL-2.0-only
"""Connection + schema helpers for the offline remediation RAG DB.

See notes/RemediationRAGPlan.txt for the design this implements. This is a
build-time authoring tool (like finetune/synth_findings.py or
finetune/batch_prep.py) — nothing in agent.py or core/tools.py imports it.

    from finetune.rag_db.db import get_connection, init_db, upsert_source, insert_chunk

Default DB file lives alongside this module, not in the repo root, so it's
obviously scoped to the RAG pipeline and not confused with
vulnerability_cache.db / trainset.db.
"""
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List

DEFAULT_DB_PATH = Path(__file__).parent / "remediation_rag.db"
_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def checksum_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Creates all tables/indexes if they don't already exist. Safe to call
    on every ingest run — schema.sql uses CREATE TABLE/INDEX IF NOT EXISTS."""
    conn = get_connection(db_path)
    conn.executescript(_SCHEMA_PATH.read_text())
    conn.commit()
    return conn


def upsert_source(
    conn: sqlite3.Connection,
    *,
    corpus: str,
    title: str,
    publisher: Optional[str],
    url: Optional[str],
    doc_version: Optional[str],
    license: str,
    platform: Optional[str],
    checksum: str,
) -> Tuple[int, bool]:
    """Inserts or updates a `sources` row, keyed by the (corpus, title,
    platform) natural key (see schema.sql's ux_sources_natural_key).

    Returns (source_id, changed) where changed=True means the checksum
    differed from what's stored (or the row is brand new) — callers should
    delete+re-insert that source's chunks in that case. changed=False means
    the caller can skip re-chunking entirely (re-ingest is a no-op)."""
    row = conn.execute(
        "SELECT source_id, checksum FROM sources WHERE corpus = ? AND title = ? "
        "AND COALESCE(platform, '') = COALESCE(?, '')",
        (corpus, title, platform),
    ).fetchone()

    if row is None:
        cur = conn.execute(
            "INSERT INTO sources (corpus, title, publisher, url, doc_version, "
            "license, platform, retrieved_at, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (corpus, title, publisher, url, doc_version, license, platform, utcnow_iso(), checksum),
        )
        return cur.lastrowid, True

    source_id = row["source_id"]
    if row["checksum"] == checksum:
        return source_id, False

    conn.execute(
        "UPDATE sources SET publisher = ?, url = ?, doc_version = ?, license = ?, "
        "retrieved_at = ?, checksum = ? WHERE source_id = ?",
        (publisher, url, doc_version, license, utcnow_iso(), checksum, source_id),
    )
    conn.execute("DELETE FROM chunks WHERE source_id = ?", (source_id,))
    return source_id, True


def insert_chunk(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    section_ref: Optional[str],
    text: str,
    finding_class_hint: Optional[str] = None,
    platform: Optional[str] = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO chunks (source_id, section_ref, text, embedding, "
        "finding_class_hint, platform) VALUES (?, ?, ?, NULL, ?, ?)",
        (source_id, section_ref, text, finding_class_hint, platform),
    )
    return cur.lastrowid


# --- Authored catalog (Draft step, notes/RemediationRAGPlan.txt "Pipeline
# shape" step 2) -- inserts into catalog_entries/catalog_steps/
# catalog_step_commands/citations. Nothing here validates command syntax or
# platform_key spelling -- finetune/command_ast_validate.py runs later
# (pipeline step 4) and is the actual enforcement point; these are dumb
# writers so a human/Claude Code session drafting an entry doesn't have to
# hand-write SQL.

def upsert_catalog_entry(
    conn: sqlite3.Connection,
    *,
    finding_class: str,
    fix_summary: str,
    status: str = "draft",
    drafted_by: Optional[str] = None,
) -> int:
    """Inserts or replaces the `catalog_entries` row for `finding_class`
    (unique key). Re-running Draft for a class you've already drafted
    overwrites `fix_summary`/`status`/`drafted_by`/`drafted_at` but leaves
    `entry_id` stable, so already-inserted `catalog_steps` rows (FK'd to
    `entry_id`) aren't orphaned -- callers that want a clean redraft should
    delete the entry's steps first (ON DELETE isn't cascading in schema.sql,
    so that's an explicit caller choice, not automatic)."""
    row = conn.execute(
        "SELECT entry_id FROM catalog_entries WHERE finding_class = ?",
        (finding_class,),
    ).fetchone()
    drafted_at = utcnow_iso()
    if row is None:
        cur = conn.execute(
            "INSERT INTO catalog_entries (finding_class, fix_summary, status, "
            "drafted_by, drafted_at) VALUES (?, ?, ?, ?, ?)",
            (finding_class, fix_summary, status, drafted_by, drafted_at),
        )
        return cur.lastrowid
    entry_id = row["entry_id"]
    conn.execute(
        "UPDATE catalog_entries SET fix_summary = ?, status = ?, drafted_by = ?, "
        "drafted_at = ? WHERE entry_id = ?",
        (fix_summary, status, drafted_by, drafted_at, entry_id),
    )
    return entry_id


def insert_catalog_step(
    conn: sqlite3.Connection,
    *,
    entry_id: int,
    step_order: int,
    step_template: str,
    requires_fields: Optional[List[str]] = None,
) -> int:
    """`requires_fields` names the `{placeholder}` fields this step's prose
    actually uses (subset of service/package/fixed_version/port/path) --
    stored as a JSON array so `fix_facts_for()`'s export-time reader can drop
    the step if the finding can't fill one, mirroring today's REMEDIATION_CATALOG
    behavior (see core/remediation.py's `_safe_format`)."""
    import json as _json
    cur = conn.execute(
        "INSERT INTO catalog_steps (entry_id, step_order, step_template, requires_fields) "
        "VALUES (?, ?, ?, ?)",
        (entry_id, step_order, step_template,
         _json.dumps(requires_fields) if requires_fields else None),
    )
    return cur.lastrowid


def insert_catalog_step_command(
    conn: sqlite3.Connection,
    *,
    step_id: int,
    platform_key: str,
    command_template: str,
    command_shell: str,
) -> int:
    """`ast_validated` stays 0 here -- populated later by
    finetune/command_ast_validate.py (pipeline step 4), never by the drafter,
    since a self-reported validation result defeats the point of an
    independent check."""
    cur = conn.execute(
        "INSERT INTO catalog_step_commands (step_id, platform_key, command_template, "
        "command_shell, ast_validated) VALUES (?, ?, ?, ?, 0)",
        (step_id, platform_key, command_template, command_shell),
    )
    return cur.lastrowid


def insert_citation(
    conn: sqlite3.Connection,
    *,
    entry_id: int,
    note: str,
    step_id: Optional[int] = None,
    chunk_id: Optional[int] = None,
    url: Optional[str] = None,
) -> int:
    """Either `chunk_id` (preferred, an ingested passage) or `url` (fallback,
    e.g. a CISA page that 403s non-browser clients -- see
    core/remediation.py's module docstring) should be set; schema.sql doesn't
    enforce that as a CHECK constraint, so it's on the caller."""
    cur = conn.execute(
        "INSERT INTO citations (entry_id, step_id, chunk_id, url, note) "
        "VALUES (?, ?, ?, ?, ?)",
        (entry_id, step_id, chunk_id, url, note),
    )
    return cur.lastrowid
