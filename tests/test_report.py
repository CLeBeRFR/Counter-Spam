"""Tests for the grouped abuse report generation."""

import pytest

from conftest import RAW_SPAM, make_sample
from counter_spam import report
from counter_spam.campaign import (LINK_DOMAIN, LINK_HOSTING, SENDING_SERVER,
                                   Finding, ReportGroup)
from counter_spam.report import build_group_report


def group_with(indexes, finding=Finding(SENDING_SERVER, "93.184.215.14"),
               organisation="Edgecast"):
    group = ReportGroup(email="abuse@edgecast.test",
                        organisation=organisation)
    for index in indexes:
        group.add(index, finding)
    return group


@pytest.fixture
def three_samples():
    return [make_sample(RAW_SPAM, f"id-{n}") for n in range(3)]


def test_single_report_structure(three_samples):
    parts = build_group_report(group_with([0, 1, 2]), three_samples)
    assert len(parts) == 1
    part = parts[0]
    assert part.recipients == ("abuse@edgecast.test",)
    assert part.subject == ("Abuse report: 3 unsolicited e-mails involving "
                            "your services")
    assert part.body.startswith("Dear Edgecast abuse team,")
    assert "sending server: 93.184.215.14 -- 3 message(s)" in part.body
    assert [name for name, _ in part.attachments] == [
        "spam-001.eml", "spam-002.eml", "spam-003.eml"]
    assert part.sample_indexes == (0, 1, 2)


def test_singular_subject_and_generic_greeting(three_samples):
    part = build_group_report(group_with([1], organisation=""),
                              three_samples)[0]
    assert part.subject == ("Abuse report: 1 unsolicited e-mail involving "
                            "your services")
    assert part.body.startswith("Dear abuse team,")


def test_message_summary_details(three_samples):
    body = build_group_report(group_with([0]), three_samples)[0].body
    assert "2026-10-31 10:00 UTC -- Votre compte est bloqué" in body
    assert "From (may be forged): PayPal Sécurité" in body
    assert "Sending IP: 93.184.215.14" in body
    assert "Authenticated domain: spam-sender.com" in body
    assert "Attachment: spam-001.eml" in body


def test_links_and_domains_are_defanged(three_samples):
    group = group_with([0], Finding(LINK_HOSTING, "104.16.1.1",
                                    "phish-site.com"))
    group.add(0, Finding(LINK_DOMAIN, "phish-site.com"))
    body = build_group_report(group, three_samples)[0].body
    assert "hxxps://login[.]phish-site[.]com/verify?id=42" in body
    assert "phish-site[.]com" in body
    assert "https://login.phish-site.com" not in body
    # IP addresses are not links: they stay copy-pasteable.
    assert "web site advertised in the message: 104.16.1.1 " \
        "(serving phish-site[.]com)" in body


def test_note_is_placed_after_greeting(three_samples):
    body = build_group_report(group_with([0]), three_samples,
                              note="  Repeated abuse.  ")[0].body
    assert body.split("\n\n")[1] == "Repeated abuse."


def test_header_values_cannot_inject_lines(three_samples):
    three_samples[0].evidence.subject = "Hi\r\nBcc: victim@example.com\n\nX"
    body = build_group_report(group_with([0]), three_samples)[0].body
    assert "Hi Bcc: victim@example.com X" in body


def test_long_values_are_truncated(three_samples):
    three_samples[0].evidence.sender = "x" * 500
    body = build_group_report(group_with([0]), three_samples)[0].body
    assert "x" * 197 + "..." in body
    assert "x" * 201 not in body


def test_split_by_message_count(monkeypatch, three_samples):
    monkeypatch.setattr(report, "MAX_MESSAGES_PER_REPORT", 2)
    parts = build_group_report(group_with([0, 1, 2]), three_samples)
    assert [part.sample_indexes for part in parts] == [(0, 1), (2,)]
    assert parts[0].subject.endswith("(part 1/2)")
    assert (parts[1].number, parts[1].total) == (2, 2)
    # Attachment numbering restarts in each part, matching its summary.
    assert [name for name, _ in parts[1].attachments] == ["spam-001.eml"]


def test_split_by_size(monkeypatch, three_samples):
    monkeypatch.setattr(report, "MAX_ATTACHMENT_BYTES_PER_REPORT",
                        len(RAW_SPAM) * 2)
    parts = build_group_report(group_with([0, 1, 2]), three_samples)
    assert [len(part.attachments) for part in parts] == [2, 1]


def test_oversized_message_is_skipped(monkeypatch, three_samples):
    monkeypatch.setattr(report, "MAX_ATTACHMENT_BYTES_PER_REPORT", 10)
    assert build_group_report(group_with([0]), three_samples) == []


@pytest.mark.parametrize("value, expected", [
    ("Sat, 31 Oct 2026 10:00:00 +0000", "2026-10-31 10:00 UTC"),
    ("Mon, 26 Oct 2026 11:27:47 +0100", "2026-10-26 10:27 UTC"),
    ("Mon, 26 Oct 2026 11:27:47 -0000", "2026-10-26 11:27"),
    ("not a date", "not a date"),
    ("", "unknown"),
])
def test_date_formatting(value, expected):
    assert report._format_date(value) == expected
