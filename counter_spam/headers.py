"""Extraction of spam evidence from a raw e-mail.

Only information added or verified by the *receiving* infrastructure is
trusted to locate the real sender:

* the IP address of the server that connected to Outlook;
* domains **authenticated** by SPF or DKIM (``spf=pass`` / ``dkim=pass``).

Everything the sender writes freely (``From``, HELO name, unverified
domains) is kept for information only: reporting a forged name would
bother an innocent third party.

Links found in the body are collected as well: the site a spam advertises
or a phishing page is often the most useful thing to take down.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urlsplit

# A hostname made of at least two RFC 1123 labels.
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)

# Authentication-Results methods; group 1 = result, group 2 = identity.
_SPF_RE = re.compile(r"\bspf=(\w+)[^;]*?\bsmtp\.mailfrom=([^;\s]+)",
                     re.IGNORECASE)
_DKIM_RE = re.compile(r"\bdkim=(\w+)[^;]*?\bheader\.[di]=@?([^;\s]+)",
                      re.IGNORECASE)

# (header name, pattern) pairs; group 1 is the extracted value.
_UNVERIFIED_DOMAIN_PATTERNS = (
    ("Received-SPF", re.compile(r"helo=([^;\s]+)")),
    ("Authentication-Results", re.compile(r"smtp\.mailfrom=([^;\s]+)")),
    ("Authentication-Results", re.compile(r"header\.[di]=@?([^;\s]+)")),
    ("DKIM-Signature", re.compile(r"(?:^|[;\s])d=([^;\s]+)")),
)
_IP_PATTERNS = (
    ("Authentication-Results", re.compile(r"sender IP is ([0-9A-Fa-f:.]+)")),
    ("Received-SPF", re.compile(r"client-ip=([0-9A-Fa-f:.]+)")),
)

#: Links kept per message: spam often carries dozens of tracking URLs.
MAX_LINKS_PER_MESSAGE = 10


@dataclass
class SpamEvidence:
    """Information gathered from one spam message."""

    sender: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    #: Public IP addresses of the server that delivered the message.
    sender_ips: list[str] = field(default_factory=list)
    #: Domains authenticated by SPF or DKIM: reliable, reportable.
    verified_domains: list[str] = field(default_factory=list)
    #: Domains merely claimed by the sender (HELO...): informational.
    unverified_domains: list[str] = field(default_factory=list)
    #: Web links found in the body (never fetched).
    links: list[str] = field(default_factory=list)
    #: Addresses the sender itself declares (``X-Report-Abuse-To``...).
    declared_abuse_contacts: list[str] = field(default_factory=list)

    @property
    def link_hosts(self) -> list[str]:
        """Hostnames of :attr:`links`, deduplicated."""
        return _unique(map(normalise_domain, map(_hostname, self.links)))

    @property
    def primary_domain(self) -> str:
        """Best guess of the domain or IP responsible for the message."""
        candidates = (self.verified_domains + self.sender_ips
                      + self.unverified_domains)
        return candidates[0] if candidates else "unknown"


def parse_message(raw: bytes) -> EmailMessage:
    """Parse raw RFC 822 bytes; header encodings are decoded on access.

    Hostile headers can make the standard library parser raise (for
    instance ``IndexError`` on a garbage ``Content-Type``).  The message is
    then parsed again without the headers it cannot handle, and as a last
    resort as a body without headers: analysis must go on.
    """
    parser = BytesParser(policy=policy.default)
    try:
        return parser.parsebytes(raw)
    except Exception:  # Stdlib parser bug triggered by hostile input.
        pass
    headers, body = _split_headers(raw)
    for candidate in (_without_broken_headers(headers) + b"\r\n" + body,
                      b"\r\n" + body):
        try:
            return parser.parsebytes(candidate)
        except Exception:  # Same as above.
            continue
    return EmailMessage()


def _split_headers(raw: bytes) -> tuple[list[tuple[str, str]], bytes]:
    """Split *raw* into raw ``(name, value)`` pairs and the body bytes."""
    legacy = BytesParser(policy=policy.compat32).parsebytes(
        raw, headersonly=True)
    payload = legacy.get_payload()
    # utf-8 + surrogateescape restores the original bytes and never fails.
    body = payload.encode("utf-8", "surrogateescape") \
        if isinstance(payload, str) else b""
    return list(legacy.raw_items()), body


def _without_broken_headers(headers: list[tuple[str, str]]) -> bytes:
    """Serialise the headers the modern parser can handle, drop the rest."""
    kept = []
    for name, value in headers:
        try:
            parsed = policy.default.header_factory(name, value)
            str(parsed)
            getattr(parsed, "params", None)
        except Exception:  # The header that broke the parser.
            continue
        line = f"{name}: {value}\r\n"
        kept.append(line.encode("utf-8", "surrogateescape"))
    return b"".join(kept)


def collect_evidence(message: EmailMessage) -> SpamEvidence:
    """Extract every useful indicator from *message*."""
    verified = _verified_domains(message)
    unverified = [domain for domain in _unique(
        map(normalise_domain, _search(message, _UNVERIFIED_DOMAIN_PATTERNS)))
        if domain not in verified]
    return SpamEvidence(
        sender=header_text(message, "From"),
        subject=header_text(message, "Subject") or "(no subject)",
        date=header_text(message, "Date"),
        message_id=header_text(message, "Message-ID"),
        sender_ips=_unique(
            map(normalise_public_ip, _search(message, _IP_PATTERNS))),
        verified_domains=verified,
        unverified_domains=unverified,
        links=extract_links(message),
        declared_abuse_contacts=_unique(
            address.lower()
            for name in ("X-Report-Abuse-To", "X-Report-Abuse")
            for value in _header_values(message, name)
            for address in _EMAIL_RE.findall(value)),
    )


def header_text(message: EmailMessage, name: str) -> str:
    """Return a decoded header as a single line, or ``""`` if missing."""
    values = _header_values(message, name)
    return " ".join(values[0].split()) if values else ""


def normalise_domain(value: str) -> str | None:
    """Return a lower-case hostname, or ``None`` if *value* is not one.

    E-mail addresses are reduced to their domain part.  This strict
    validation also guarantees that attacker-controlled content is never
    passed as-is to network lookups.
    """
    value = value.strip().strip("<>\"'").rstrip(".").lower()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value if _DOMAIN_RE.match(value) else None


def normalise_public_ip(value: str) -> str | None:
    """Return *value* if it is a globally routable IP address."""
    try:
        address = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    # Private, loopback... addresses belong to internal relays and have no
    # meaningful abuse contact.
    return str(address) if address.is_global else None


def extract_links(message: EmailMessage) -> list[str]:
    """Return the web links of the body: plain-text URLs and ``<a href>``.

    Image sources, style sheets and XML namespaces are ignored on purpose:
    they mostly point to CDNs or standards bodies, not to the spammer.
    """
    links: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == \
                "attachment":
            continue
        subtype = part.get_content_subtype()
        if part.get_content_maintype() != "text" or \
                subtype not in ("plain", "html"):
            continue
        text = part_text(part)
        if subtype == "html":
            links.extend(_HrefCollector.collect(text))
        else:
            links.extend(_URL_RE.findall(text))
    web_links = (url.rstrip(".,;:!?") for url in links
                 if normalise_domain(_hostname(url)))
    return _unique(web_links)[:MAX_LINKS_PER_MESSAGE]


def _hostname(url: str) -> str:
    """Return the host of an http(s) URL, or ``""`` (never raises)."""
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            return ""
        return parts.hostname or ""
    except ValueError:  # e.g. "Invalid IPv6 URL" for "https://[abc".
        return ""


def defang(text: str) -> str:
    """Make a URL or domain non-clickable (``hxxps://example[.]com``)."""
    return re.sub(r"^http", "hxxp", text, flags=re.IGNORECASE) \
        .replace(".", "[.]")


class _HrefCollector(HTMLParser):
    """Collect the targets of ``<a href>`` links of an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href.strip())

    @classmethod
    def collect(cls, html: str) -> list[str]:
        parser = cls()
        parser.feed(html)
        parser.close()
        return parser.hrefs


def part_text(part: EmailMessage) -> str:
    """Return the decoded text of a MIME part, tolerating bad charsets."""
    try:
        return part.get_content()
    except Exception:  # Unknown charset, bad encoding, empty payload...
        payload = part.get_payload(decode=True) or b""
        if not isinstance(payload, bytes):
            return ""
        return payload.decode("utf-8", errors="replace")


def _verified_domains(message: EmailMessage) -> list[str]:
    """Return domains whose SPF or DKIM check passed at reception."""
    found = []
    for value in _header_values(message, "Authentication-Results"):
        for pattern in (_DKIM_RE, _SPF_RE):
            for result, identity in pattern.findall(value):
                if result.lower() == "pass":
                    found.append(normalise_domain(identity))
    return _unique(found)


def _header_values(message: EmailMessage, name: str) -> list[str]:
    """Return all decoded values of a header, tolerating malformed ones.

    The standard library parses structured headers (``From``, ``To``...)
    lazily and some hostile values make it raise unexpected exceptions
    (``AttributeError``...).  One booby-trapped spam must not stop the
    analysis of the others, so any failure falls back to the raw value.
    """
    try:
        parsed = message.get_all(name) or []
    except Exception:  # Stdlib parser bug triggered by hostile input.
        parsed = [value for key, value in message.raw_items()
                  if key.lower() == name.lower()]
    values = []
    for value in parsed:
        try:
            values.append(str(value))
        except Exception:  # Undecodable value: skip it.
            continue
    return values


def _search(message: EmailMessage,
            patterns: Iterable[tuple[str, re.Pattern]]) -> Iterable[str]:
    """Yield every match of the ``(header, pattern)`` pairs."""
    for name, pattern in patterns:
        for value in _header_values(message, name):
            yield from pattern.findall(value)


def _unique(values: Iterable[str | None]) -> list[str]:
    """Drop empty values and duplicates while preserving the order."""
    return [value for value in dict.fromkeys(values) if value]
