"""Generation of the grouped abuse reports.

One report is written per abuse desk.  It lists every spam concerning the
desk with the evidence that relates to it, and attaches the original
messages (``.eml``, full headers) so the desk can verify everything.
Large groups are split into several parts to respect ``sendMail`` limits.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Sequence

from .campaign import FINDING_LABELS, LINK_DOMAIN, LINK_HOSTING, \
    ReportGroup, Sample
from .headers import defang, normalise_public_ip

#: Every report subject starts with this: replies are recognised by it.
REPORT_SUBJECT_PREFIX = "Abuse report:"

#: Raw size budget of the attachments of one report.  Base64 inflates it
#: by a third, which keeps us below Graph's 3 MB inline limit.
MAX_ATTACHMENT_BYTES_PER_REPORT = 2_000_000
#: Keeps reports readable and below per-message attachment limits.
MAX_MESSAGES_PER_REPORT = 40
#: Longest subject kept in the summary table.
_SUBJECT_WIDTH = 70


@dataclass(frozen=True)
class ReportPart:
    """One e-mail to send to an abuse desk."""

    recipients: tuple[str, ...]
    subject: str
    body: str
    attachments: tuple[tuple[str, bytes], ...]
    sample_indexes: tuple[int, ...]
    number: int = 1
    total: int = 1


def _one_line(value: str, max_length: int = 200) -> str:
    """Collapse whitespace and truncate a value taken from a spam.

    Spam content is attacker-controlled: this keeps it from injecting
    extra lines or paragraphs into the report.
    """
    value = " ".join(value.split())
    if len(value) > max_length:
        value = value[:max_length - 3] + "..."
    return value or "unknown"


def _format_date(value: str) -> str:
    """Return a ``YYYY-MM-DD HH:MM UTC`` date, or the raw header value."""
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return _one_line(value, 40)
    if moment.tzinfo is None:
        return moment.strftime("%Y-%m-%d %H:%M")
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _chunks(indexes: Sequence[int], samples: Sequence[Sample]):
    """Split sample indexes into parts respecting the size budgets."""
    chunk: list[int] = []
    size = 0
    for index in indexes:
        length = len(samples[index].raw)
        if length > MAX_ATTACHMENT_BYTES_PER_REPORT:
            continue  # Cannot be attached inline at all; skipped.
        if chunk and (size + length > MAX_ATTACHMENT_BYTES_PER_REPORT
                      or len(chunk) >= MAX_MESSAGES_PER_REPORT):
            yield chunk
            chunk, size = [], 0
        chunk.append(index)
        size += length
    if chunk:
        yield chunk


def _responsibilities(group: ReportGroup, indexes: Sequence[int]) -> str:
    """Bullet list of the resources of the desk involved in this part."""
    lines = {}
    for index in indexes:
        for finding in group.entries[index]:
            label = FINDING_LABELS.get(finding.kind, finding.kind)
            resource = finding.resource
            # Domains are defanged so they cannot be clicked by mistake;
            # IP addresses stay as is, ready to paste in abuse tools.
            if finding.kind in (LINK_DOMAIN, LINK_HOSTING) and \
                    not normalise_public_ip(resource):
                resource = defang(resource)
            text = f"{label}: {resource}"
            if finding.via:
                text += f" (serving {defang(finding.via)})"
            lines[text] = lines.get(text, 0) + 1
    return "\n".join(f"  - {text} -- {count} message(s)"
                     for text, count in lines.items())


def _summary(indexes: Sequence[int], samples: Sequence[Sample]) -> str:
    """Numbered summary of the messages of this part."""
    blocks = []
    for number, index in enumerate(indexes, 1):
        evidence = samples[index].evidence
        lines = [f"{number:>3}. {_format_date(evidence.date)} -- "
                 f"{_one_line(evidence.subject, _SUBJECT_WIDTH)}",
                 f"     From (may be forged): {_one_line(evidence.sender)}"]
        if evidence.sender_ips:
            lines.append("     Sending IP: " + ", ".join(evidence.sender_ips))
        if evidence.verified_domains:
            lines.append("     Authenticated domain: "
                         + ", ".join(evidence.verified_domains))
        if evidence.links:
            lines.append("     Links: " + ", ".join(
                defang(_one_line(url, 120)) for url in evidence.links[:5]))
        lines.append(f"     Attachment: {_attachment_name(number)}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _attachment_name(number: int) -> str:
    return f"spam-{number:03d}.eml"


def build_group_report(group: ReportGroup, samples: Sequence[Sample], *,
                       note: str = "") -> list[ReportPart]:
    """Return the e-mail(s) reporting *group* to its abuse desk.

    Args:
        group: the abuse desk and its findings.
        samples: every sample of the plan (indexed by the group entries).
        note: optional personal message inserted at the top.
    """
    indexes = sorted(group.entries)
    chunks = list(_chunks(indexes, samples))
    parts = []
    for number, chunk in enumerate(chunks, 1):
        suffix = f" (part {number}/{len(chunks)})" if len(chunks) > 1 else ""
        count = len(chunk)
        subject = (f"{REPORT_SUBJECT_PREFIX} {count} unsolicited e-mail"
                   f"{'s' if count > 1 else ''} involving your services"
                   f"{suffix}")
        greeting = f"Dear {group.organisation} abuse team," \
            if group.organisation else "Dear abuse team,"
        body = "\n\n".join(filter(None, [
            greeting,
            note.strip(),
            f"I received the {count} unsolicited e-mail"
            f"{'s' if count > 1 else ''} (spam / phishing) listed below. "
            "They involve resources under your responsibility:",
            _responsibilities(group, chunk),
            "Summary of the messages (links are defanged; the original "
            "messages, with full headers, are attached as .eml files):",
            _summary(chunk, samples),
            "I would be grateful if you could investigate and take the "
            "appropriate action (suspension of the accounts, servers or "
            "domains involved).",
            "This report was prepared with Counter-Spam on behalf of the "
            "recipient of these messages. Replies are read.",
            "Best regards.",
        ]))
        attachments = tuple(
            (_attachment_name(position), samples[index].raw)
            for position, index in enumerate(chunk, 1))
        parts.append(ReportPart(
            recipients=(group.email,), subject=subject, body=body,
            attachments=attachments, sample_indexes=tuple(chunk),
            number=number, total=len(chunks)))
    return parts
