-- SPDX-License-Identifier: GPL-2.0-only
-- Offline remediation RAG DB schema — verbatim from notes/RemediationRAGPlan.txt
-- "## Schema". This file is the single source of truth for the DDL; db.py
-- executes it with CREATE TABLE IF NOT EXISTS semantics (see below) so
-- init_db() is safe to re-run against an existing remediation_rag.db.
--
-- This is a build-time authoring tool, not a runtime dependency. Nothing in
-- agent.py or core/tools.py opens this database.

-- ── Corpus ──────────────────────────────────────────────────────────────────
-- One row per ingested document: a ComplianceAsCode rule-group page, an mSCP
-- baseline control, a vendor advisory page, a distro patch-notes page, etc.
-- See notes/RemediationRAGPlan.txt "Sources" for what's active vs. deferred.
CREATE TABLE IF NOT EXISTS sources (
    source_id    INTEGER PRIMARY KEY,
    corpus       TEXT NOT NULL,   -- 'complianceascode' | 'mscp' | 'vendor_advisory'
                                   -- | 'distro_patchnotes' | 'nvd' | 'kev' | 'other'
                                   -- ('mscp' rows are schema-valid but not populated
                                   -- until a macOS-native audit scanner exists)
    title        TEXT NOT NULL,
    publisher    TEXT,            -- 'ComplianceAsCode', 'NIST/mSCP', 'Debian', 'Microsoft', ...
    url          TEXT,
    doc_version  TEXT,            -- e.g. "ComplianceAsCode content @<git-sha>"
    license      TEXT NOT NULL,   -- 'bsd_3_clause' | 'cc_by_4_0' | 'public_domain' | ...
    platform     TEXT,            -- 'linux' | 'windows' | 'darwin' | NULL (agnostic)
    retrieved_at TEXT NOT NULL,
    checksum     TEXT NOT NULL    -- content hash; re-ingest is a no-op if unchanged
);

-- Natural key for dedup on re-ingest: same document identified again should
-- update in place (and re-chunk only if checksum changed), not duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS ux_sources_natural_key
    ON sources (corpus, title, COALESCE(platform, ''));

-- Chunked passages — the retrieval unit. Kept short (a control/rule/paragraph)
-- so a query returns a specific grounding passage, not a whole document.
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id           INTEGER PRIMARY KEY,
    source_id          INTEGER NOT NULL REFERENCES sources(source_id),
    section_ref        TEXT,       -- ComplianceAsCode rule ID (e.g. "sshd_disable_root_login"),
                                    -- mSCP rule ID (e.g. "os_gatekeeper_enable"), section heading
    text                TEXT NOT NULL,
    embedding           BLOB,       -- vector for similarity search (NULL until the
                                    -- embedding backend question is settled — see
                                    -- notes/RemediationRAGPlan.txt "Open questions")
    finding_class_hint TEXT,      -- optional pre-tag ('rce', 'default_creds', ...) to
                                    -- narrow retrieval before the embedding search runs
    platform            TEXT
);

CREATE INDEX IF NOT EXISTS ix_chunks_source ON chunks (source_id);
CREATE INDEX IF NOT EXISTS ix_chunks_finding_class_hint ON chunks (finding_class_hint);

-- Records which embedding model produced the vectors currently sitting in
-- chunks.embedding, and when. Not per-chunk -- one run covers however many
-- chunks embed_chunks.py processed in a pass. Exists so a future model
-- switch is visible (mixing vectors from two different embedding spaces in
-- one similarity search silently produces garbage rankings) rather than
-- something only discoverable by noticing bad retrieval results later.
CREATE TABLE IF NOT EXISTS embedding_runs (
    run_id       INTEGER PRIMARY KEY,
    model        TEXT NOT NULL,       -- e.g. 'nomic-embed-text', 'mxbai-embed-large'
    backend      TEXT NOT NULL DEFAULT 'ollama',
    dimensions   INTEGER NOT NULL,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    chunk_count  INTEGER NOT NULL DEFAULT 0
);

-- ── Authored catalog (the RAG DB's output) ─────────────────────────────────
-- Same key space as today's REMEDIATION_CATALOG — one row per finding class.
CREATE TABLE IF NOT EXISTS catalog_entries (
    entry_id      INTEGER PRIMARY KEY,
    finding_class TEXT NOT NULL UNIQUE, -- same enum as core/remediation.py's classifiers
    fix_summary   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'draft',  -- 'draft'|'needs_changes'|'approved'|'published'
    drafted_by    TEXT,                -- model/run id that proposed this draft
    drafted_at    TEXT
);

-- Ordered, platform-agnostic steps within an entry. Pure prose — the
-- {service}/{package}/{fixed_version}/{port} template a report renders
-- regardless of OS. Platform-specific commands hang off this row (below),
-- not on it, since the same step often has 3-4 command variants.
CREATE TABLE IF NOT EXISTS catalog_steps (
    step_id         INTEGER PRIMARY KEY,
    entry_id        INTEGER NOT NULL REFERENCES catalog_entries(entry_id),
    step_order      INTEGER NOT NULL,
    step_template   TEXT NOT NULL,      -- prose, e.g. "Update {service} to {fixed_version}."
    requires_fields TEXT,               -- JSON array of placeholder names; if the finding
                                         -- can't fill one, fix_facts_for() drops this step
                                         -- entirely — same "no filler" rule as today
    UNIQUE (entry_id, step_order)
);

-- The platform-wise commands_template field: one row per (step, platform,
-- package manager) variant. Every row is exactly ONE shell invocation — no
-- `&&`/`;` chaining. See notes/RemediationRAGPlan.txt for the full rationale.
CREATE TABLE IF NOT EXISTS catalog_step_commands (
    command_id       INTEGER PRIMARY KEY,
    step_id          INTEGER NOT NULL REFERENCES catalog_steps(step_id),
    platform_key     TEXT NOT NULL,    -- 'linux_apt' | 'linux_dnf' | 'linux_pacman' |
                                        -- 'darwin_brew' | 'windows_powershell' |
                                        -- 'windows_winget' — fixed enum, see validator
    command_template TEXT NOT NULL,    -- e.g. "sudo apt-get install --only-upgrade {package}"
    command_shell    TEXT NOT NULL,    -- 'bash' | 'powershell' — drives which AST check runs
    ast_validated    INTEGER NOT NULL DEFAULT 0,
    ast_validator    TEXT,             -- e.g. 'shlex+allowlist:v1', 'ps_parser+allowlist:v1'
    ast_error        TEXT,             -- reason for the last failed validation, else NULL
    ast_checked_at   TEXT,
    UNIQUE (step_id, platform_key)
);

-- Provenance: links a catalog entry or a single step back to the corpus
-- passage(s) that justify it. Replaces the hand-written _CITE_* comments.
CREATE TABLE IF NOT EXISTS citations (
    citation_id INTEGER PRIMARY KEY,
    entry_id    INTEGER NOT NULL REFERENCES catalog_entries(entry_id),
    step_id     INTEGER REFERENCES catalog_steps(step_id),  -- NULL = grounds whole entry
    chunk_id    INTEGER REFERENCES chunks(chunk_id),         -- preferred: a specific passage
    url         TEXT,               -- fallback when there's no ingested chunk (e.g. a
                                     -- CISA page that 403s non-browser clients)
    note        TEXT NOT NULL       -- one line: why this source grounds this step
);

-- Human review trail — the approval gate. A step/entry only exports if its
-- latest review is 'approved'.
CREATE TABLE IF NOT EXISTS reviews (
    review_id   INTEGER PRIMARY KEY,
    entry_id    INTEGER NOT NULL REFERENCES catalog_entries(entry_id),
    reviewer    TEXT NOT NULL,
    decision    TEXT NOT NULL,      -- 'approved' | 'rejected' | 'needs_changes'
    comment     TEXT,
    reviewed_at TEXT NOT NULL
);
