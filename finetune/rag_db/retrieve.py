# SPDX-License-Identifier: GPL-2.0-only
"""Retrieval step for the offline Draft pass (notes/RemediationRAGPlan.txt
"Pipeline shape" step 2) -- given a finding_class (or an arbitrary query),
returns the top-k grounding chunks for a human/Claude Code session to read
before drafting `catalog_entries`/`catalog_steps`/`catalog_step_commands`
rows. Not itself a drafting tool -- it only surfaces passages.

Cosine similarity over `chunks.embedding`, computed in Python (stdlib only,
matching embeddings.py's no-numpy choice) -- the corpus is ~1k chunks, small
enough that an in-memory scan per query is instant; no need for a vector
index.

Usage:
    python3 -m finetune.rag_db.retrieve --finding-class rce --top-k 8
    python3 -m finetune.rag_db.retrieve --query "disable SMBv1" --platform windows
    python3 -m finetune.rag_db.retrieve --finding-class-hint SMB1-ENABLED --json
"""
import argparse
import json
import math
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from finetune.rag_db.db import DEFAULT_DB_PATH, get_connection
from finetune.rag_db.embeddings import blob_to_vector
from finetune.rag_db.embed_chunks import embed_text, _DEFAULT_OLLAMA_HOST

_DEFAULT_EMBED_MODEL = "nomic-embed-text"


def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def retrieve(
    conn,
    query_text: str,
    *,
    finding_class_hint: Optional[str] = None,
    platform: Optional[str] = None,
    top_k: int = 8,
    embed_model: str = _DEFAULT_EMBED_MODEL,
    embed_host: str = _DEFAULT_OLLAMA_HOST,
) -> List[dict]:
    """Embeds `query_text` and ranks chunks by cosine similarity, optionally
    narrowed by `finding_class_hint` (exact match) and/or `platform`. Chunks
    with no embedding yet are skipped (see embed_chunks.py)."""
    query_vec = embed_text(embed_host, embed_model, query_text)

    sql = (
        "SELECT c.chunk_id, c.section_ref, c.text, c.embedding, c.finding_class_hint, "
        "c.platform, s.title, s.publisher, s.url, s.corpus, s.license "
        "FROM chunks c JOIN sources s ON s.source_id = c.source_id "
        "WHERE c.embedding IS NOT NULL"
    )
    params: List[str] = []
    if finding_class_hint is not None:
        sql += " AND c.finding_class_hint = ?"
        params.append(finding_class_hint)
    if platform is not None:
        sql += " AND (c.platform = ? OR c.platform IS NULL)"
        params.append(platform)

    rows = conn.execute(sql, params).fetchall()

    scored = []
    for row in rows:
        vec = blob_to_vector(row["embedding"])
        score = _cosine(query_vec, vec)
        scored.append((score, row))

    scored.sort(key=lambda pair: pair[0], reverse=True)

    results = []
    for score, row in scored[:top_k]:
        results.append({
            "chunk_id": row["chunk_id"],
            "score": round(score, 4),
            "section_ref": row["section_ref"],
            "text": row["text"],
            "finding_class_hint": row["finding_class_hint"],
            "platform": row["platform"],
            "source_title": row["title"],
            "publisher": row["publisher"],
            "url": row["url"],
            "corpus": row["corpus"],
            "license": row["license"],
        })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--query", help="free-text query; defaults to --finding-class if omitted")
    parser.add_argument("--finding-class", help="finding class enum value, e.g. 'rce', 'default_creds'")
    parser.add_argument("--finding-class-hint", help="exact chunks.finding_class_hint filter "
                         "(defaults to --finding-class if that's set and this isn't)")
    parser.add_argument("--platform", choices=["linux", "windows", "darwin"], default=None)
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--model", default=_DEFAULT_EMBED_MODEL)
    parser.add_argument("--host", default=_DEFAULT_OLLAMA_HOST)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.query and not args.finding_class:
        parser.error("pass --query and/or --finding-class")

    query_text = args.query or args.finding_class
    hint = args.finding_class_hint if args.finding_class_hint is not None else args.finding_class

    conn = get_connection(args.db_path)
    results = retrieve(
        conn, query_text,
        finding_class_hint=hint,
        platform=args.platform,
        top_k=args.top_k,
        embed_model=args.model,
        embed_host=args.host,
    )
    conn.close()

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    if not results:
        print("[OK] no matching chunks (check --finding-class-hint spelling, or drop the filter).")
        return 0

    for r in results:
        print(f"--- chunk_id={r['chunk_id']} score={r['score']} hint={r['finding_class_hint']} "
              f"platform={r['platform']} ---")
        print(f"{r['source_title']} ({r['publisher']}) {r['url']}")
        if r["section_ref"]:
            print(f"section: {r['section_ref']}")
        print(r["text"][:500])
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
