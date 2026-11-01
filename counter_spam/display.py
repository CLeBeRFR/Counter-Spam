"""Safe rendering of untrusted e-mail content in a terminal.

Spam is hostile input.  Its text is therefore

* stripped of control characters, so ANSI/OSC escape sequences cannot
  rewrite the terminal, forge output or set the clipboard;
* converted from HTML to plain text locally, without ever opening a
  browser nor fetching remote content (tracking pixels, scripts...).
"""

from __future__ import annotations

import re
import unicodedata
from email.message import EmailMessage
from html.parser import HTMLParser

from .headers import part_text

# Characters kept despite being in the Unicode "C*" categories.
_ALLOWED_CONTROLS = frozenset("\n\t")
_BLANK_LINES_RE = re.compile(r"\n\s*\n(\s*\n)+")


def sanitize(text: str) -> str:
    """Remove control and format characters (except newline and tab).

    Category ``Cf`` covers bidirectional overrides, which could otherwise
    visually reorder the displayed text.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(
        char for char in text
        if char in _ALLOWED_CONTROLS
        or not unicodedata.category(char).startswith("C"))


class _TextExtractor(HTMLParser):
    """Collect the visible text of an HTML document."""

    _SKIPPED_TAGS = frozenset({"script", "style", "head", "title"})
    _BLOCK_TAGS = frozenset({"br", "p", "div", "tr", "li", "h1", "h2",
                             "h3", "h4", "h5", "h6", "table"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIPPED_TAGS:
            self._skip_depth += 1
        elif tag in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIPPED_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def html_to_text(html: str) -> str:
    """Return the visible text of *html*."""
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return parser.text()


def message_text(message: EmailMessage) -> str:
    """Return the readable body of *message*, sanitised for the terminal.

    The plain-text alternative is preferred; HTML is converted locally.
    Attachments are listed but never decoded nor saved.
    """
    body = message.get_body(preferencelist=("plain", "html"))
    text = ""
    if body is not None:
        text = part_text(body)
        if body.get_content_subtype() == "html":
            text = html_to_text(text)

    attachments = [part.get_filename() or "(unnamed)"
                   for part in message.iter_attachments()]
    if attachments:
        text += "\n\n[Attachments not opened: " + ", ".join(attachments) + "]"

    text = _BLANK_LINES_RE.sub("\n\n", sanitize(text))
    return text.strip() or "(empty body)"
