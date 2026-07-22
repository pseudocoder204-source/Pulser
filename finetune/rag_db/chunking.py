# SPDX-License-Identifier: GPL-2.0-only
"""Shared text-chunking helpers for the RAG ingestion scripts.

Kept deliberately dumb (paragraph/whitespace splitting, no NLP dependency) —
this is a build-time tool where a human reviews the ingested skeleton before
anything downstream trusts it, per notes/RemediationRAGPlan.txt's Review gate.
"""
import re
from typing import List

_WS_RE = re.compile(r"[ \t]+")
_BLANK_LINES_RE = re.compile(r"\n{2,}")


def normalize_whitespace(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [_WS_RE.sub(" ", line).strip() for line in text.split("\n")]
    return "\n".join(lines).strip()


def split_paragraphs(text: str, min_len: int = 40) -> List[str]:
    """Splits on blank lines, drops paragraphs shorter than min_len (nav
    cruft, single-word headings picked up by a naive HTML-to-text pass)."""
    text = normalize_whitespace(text)
    paragraphs = [p.strip() for p in _BLANK_LINES_RE.split(text)]
    return [p for p in paragraphs if len(p) >= min_len]


def merge_short_paragraphs(paragraphs: List[str], target_len: int = 800, max_len: int = 1500) -> List[str]:
    """Coalesces adjacent short paragraphs up to ~target_len chars so chunks
    are neither one-sentence fragments nor whole-page walls of text. Never
    merges past max_len."""
    merged: List[str] = []
    buf = ""
    for p in paragraphs:
        candidate = f"{buf}\n\n{p}" if buf else p
        if buf and len(candidate) > max_len:
            merged.append(buf)
            buf = p
        else:
            buf = candidate
            if len(buf) >= target_len:
                merged.append(buf)
                buf = ""
    if buf:
        merged.append(buf)
    return merged
