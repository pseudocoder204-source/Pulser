# SPDX-License-Identifier: GPL-2.0-only
"""Minimal HTML-to-text extraction, stdlib only (no bs4/lxml dependency).

Good enough for chunking advisory/patch-notes pages into paragraphs — not a
general-purpose readability extractor. Strips <script>/<style>/<nav>/<header>/
<footer> content entirely and inserts blank-line breaks at block-level tags
so chunking.split_paragraphs() has real paragraph boundaries to split on.
"""
from html.parser import HTMLParser

_SKIP_TAGS = {"script", "style", "noscript", "svg", "form"}
_BLOCK_TAGS = {
    "p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "br", "tr", "section", "article", "pre", "blockquote",
}


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data):
        if self._skip_depth == 0 and data.strip():
            self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def html_to_text(html: str) -> str:
    extractor = _TextExtractor()
    extractor.feed(html)
    extractor.close()
    return extractor.get_text()
