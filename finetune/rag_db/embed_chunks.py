# SPDX-License-Identifier: GPL-2.0-only
"""Populates chunks.embedding via a local Ollama embedding model.

Decided: embeddings are computed by a strong Ollama-hosted embedding model
(the "local, no network call" option from notes/RemediationRAGPlan.txt's
Open Questions -- Ollama already runs locally for agent.py's report stage,
so this reuses the same backend rather than adding a second inference
dependency). Pull an embedding model first, e.g.:

    ollama pull nomic-embed-text
    ollama pull mxbai-embed-large

Then:

    python3 -m finetune.rag_db.embed_chunks --model nomic-embed-text
    python3 -m finetune.rag_db.embed_chunks --model nomic-embed-text --reembed
    python3 -m finetune.rag_db.embed_chunks --model nomic-embed-text --limit 20 --dry-run

By default only chunks with `embedding IS NULL` are processed, so this is
safe to re-run after every ingest pass without recomputing existing vectors.
`--reembed` forces every chunk to be recomputed -- use this after switching
models, since mixing vectors from two embedding spaces in one similarity
search silently produces meaningless rankings (see the embedding_runs table
in schema.sql). Each run is recorded there with the model name + vector
dimensionality so a stale/mixed embedding space is visible in the DB, not
just discoverable via bad retrieval results later.
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import requests

from finetune.rag_db.db import DEFAULT_DB_PATH, get_connection, init_db, utcnow_iso
from finetune.rag_db.embeddings import vector_to_blob

_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_TIMEOUT_S = 60


def embed_text(host: str, model: str, text: str) -> List[float]:
    resp = requests.post(
        f"{host}/api/embeddings",
        json={"model": model, "prompt": text},
        timeout=_TIMEOUT_S,
    )
    resp.raise_for_status()
    data = resp.json()
    embedding = data.get("embedding")
    if not embedding:
        raise RuntimeError(f"Ollama returned no embedding: {data}")
    return embedding


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--model", required=True, help="Ollama embedding model tag, e.g. nomic-embed-text")
    parser.add_argument("--host", default=_DEFAULT_OLLAMA_HOST)
    parser.add_argument("--reembed", action="store_true",
                         help="recompute every chunk's embedding, not just NULL ones")
    parser.add_argument("--limit", type=int, default=None, help="only embed the first N pending chunks (for review)")
    parser.add_argument("--commit-every", type=int, default=25)
    parser.add_argument("--dry-run", action="store_true", help="call the model but don't write to the DB")
    args = parser.parse_args()

    conn = get_connection(args.db_path) if args.dry_run else init_db(args.db_path)

    where = "" if args.reembed else "WHERE embedding IS NULL"
    query = f"SELECT chunk_id, text FROM chunks {where} ORDER BY chunk_id"
    if args.limit:
        query += f" LIMIT {int(args.limit)}"
    rows = conn.execute(query).fetchall()

    if not rows:
        print("[OK] no chunks need embedding (nothing matched embedding IS NULL; pass --reembed to force).")
        conn.close()
        return 0

    started_at = utcnow_iso()
    embedded = 0
    dimensions: Optional[int] = None
    failures = 0

    for i, row in enumerate(rows, start=1):
        try:
            vector = embed_text(args.host, args.model, row["text"])
        except (requests.RequestException, RuntimeError) as exc:
            print(f"[WARN] chunk_id={row['chunk_id']}: embedding failed -- {exc}", file=sys.stderr)
            failures += 1
            continue

        dimensions = dimensions or len(vector)
        if len(vector) != dimensions:
            print(f"[WARN] chunk_id={row['chunk_id']}: dimension {len(vector)} != expected {dimensions} "
                  "-- model may have changed mid-run, skipping", file=sys.stderr)
            failures += 1
            continue

        if not args.dry_run:
            conn.execute("UPDATE chunks SET embedding = ? WHERE chunk_id = ?",
                         (vector_to_blob(vector), row["chunk_id"]))
            if i % args.commit_every == 0:
                conn.commit()
        embedded += 1
        if i % 50 == 0 or i == len(rows):
            print(f"[PROGRESS] {i}/{len(rows)} chunk(s) processed ({failures} failure(s))")

    if not args.dry_run:
        conn.commit()
        conn.execute(
            "INSERT INTO embedding_runs (model, backend, dimensions, started_at, completed_at, chunk_count) "
            "VALUES (?, 'ollama', ?, ?, ?, ?)",
            (args.model, dimensions or 0, started_at, utcnow_iso(), embedded),
        )
        conn.commit()

    conn.close()
    print(f"\n[OK] {embedded} chunk(s) embedded with {args.model!r} (dim={dimensions}), {failures} failure(s).")
    return 1 if failures and embedded == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
