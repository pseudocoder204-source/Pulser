# SPDX-License-Identifier: GPL-2.0-only
"""Vector <-> BLOB (de)serialization for chunks.embedding.

Stdlib-only (the `array` module) rather than numpy -- this is a thin
serialization shim, not numeric code, and keeps the RAG tooling's dependency
footprint small. Format: raw little-endian float32, no header -- the
embedding dimension is implied by len(blob) // 4 and is expected to be
constant per (embedding backend, model) pair, which is why
embed_chunks.py stamps the model name into sources.doc_version-adjacent
bookkeeping (see that module) rather than storing it per-chunk.
"""
import array
from typing import List


def vector_to_blob(vector: List[float]) -> bytes:
    return array.array("f", vector).tobytes()


def blob_to_vector(blob: bytes) -> List[float]:
    arr = array.array("f")
    arr.frombytes(blob)
    return list(arr)
