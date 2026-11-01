"""Tests for the safe rendering of untrusted e-mail content."""

import pytest

from counter_spam.display import html_to_text, message_text, sanitize
from counter_spam.headers import parse_message


@pytest.mark.parametrize("value, expected", [
    ("\x1b[31mred\x1b[0m", "[31mred[0m"),        # ANSI CSI stripped of ESC
    ("\x1b]52;c;ZXZpbA==\x07", "]52;c;ZXZpbA=="),  # OSC 52 clipboard write
    ("été‮gnp.exe", "étégnp.exe"),           # Bidi override
    ("a​b", "ab"),                           # Zero-width space
    ("line1\r\nline2\rline3", "line1\nline2\nline3"),
    ("tab\tkept", "tab\tkept"),
    ("emoji 🎰 kept", "emoji 🎰 kept"),
])
def test_sanitize(value, expected):
    assert sanitize(value) == expected


def test_html_is_converted_without_scripts():
    html = ("<html><head><title>T</title><style>x{}</style></head><body>"
            "<p>Hi</p><script>alert(1)</script>"
            "<img src='https://track/p.gif'></body></html>")
    assert html_to_text(html).strip() == "Hi"


def test_html_entities_are_decoded():
    assert html_to_text("<p>A &amp; B &lt;3</p>").strip() == "A & B <3"


def test_plain_text_preferred(spam_message):
    text = message_text(spam_message)
    assert text.startswith("Click here")
    assert "\x1b" not in text


def test_html_only_message():
    raw = (b"Content-Type: text/html; charset=utf-8\r\n\r\n"
           b"<p>Bonjour</p><p>Gagnez</p>")
    assert message_text(parse_message(raw)) == "Bonjour\n\nGagnez"


def test_attachments_are_listed_not_opened():
    raw = (b"MIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=z\r\n\r\n"
           b"--z\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
           b"--z\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Disposition: attachment; filename=\"invoice.exe\"\r\n"
           b"\r\nTVqQ\r\n--z--\r\n")
    text = message_text(parse_message(raw))
    assert text == "Hello\n\n[Attachments not opened: invoice.exe]"


def test_bad_charset_falls_back_to_utf8():
    raw = b"Content-Type: text/plain; charset=x-unknown\r\n\r\nCaf\xc3\xa9"
    assert message_text(parse_message(raw)) == "Café"


def test_empty_body():
    assert message_text(parse_message(b"Subject: x\r\n\r\n")) == \
        "(empty body)"


def test_empty_message_object():
    from email.message import EmailMessage

    assert message_text(EmailMessage()) == "(empty body)"
