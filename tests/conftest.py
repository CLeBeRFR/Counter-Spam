"""Shared fixtures: realistic spam messages and fakes for network access."""

from __future__ import annotations

from email.message import EmailMessage
from unittest import mock

import pytest

from counter_spam.campaign import Sample
from counter_spam.headers import parse_message
from counter_spam.rdap import AbuseLookup

# Headers as added by Exchange Online Protection to an incoming spam.
RAW_SPAM = b"""\
Received-SPF: Pass (protection.outlook.com: domain of spam-sender.com\r
 designates 203.0.113.7 as permitted sender) receiver=protection.outlook.com;\r
 client-ip=93.184.215.14; helo=mail.spam-sender.com; pr=C\r
Authentication-Results: spf=pass (sender IP is 93.184.215.14)\r
 smtp.mailfrom=bounces.spam-sender.com; dkim=pass (signature was verified)\r
 header.d=spam-sender.com;dmarc=pass action=none header.from=paypal.com;\r
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=spam-sender.com;\r
 s=s1; h=from:subject; bh=abc=; b=def=\r
X-Report-Abuse-To: abuse@spam-sender.com\r
From: =?utf-8?q?PayPal_S=C3=A9curit=C3=A9?= <security@paypal.com>\r
Subject: =?utf-8?b?Vm90cmUgY29tcHRlIGVzdCBibG9xdcOp?=\r
Date: Sat, 31 Oct 2026 10:00:00 +0000\r
Message-ID: <abc@spam-sender.com>\r
Content-Type: text/plain; charset=utf-8\r
\r
Click here \x1b[31mnow\x1b[0m: https://login.phish-site.com/verify?id=42\r
"""

# A spam whose SPF / DKIM checks failed: its domains are only claimed.
RAW_UNAUTHENTICATED = b"""\
Received-SPF: None (protection.outlook.com: forged.example does not\r
 designate permitted sender hosts) client-ip=20.12.182.63;\r
 helo=webassembly.github.io;\r
Authentication-Results: spf=none (sender IP is 20.12.182.63)\r
 smtp.mailfrom=forged.example; dkim=fail (signature did not verify)\r
 header.d=forged-dkim.example;dmarc=none action=none header.from=x.com;\r
From: Casino <no-reply@casino.example>\r
Subject: Bonus 400 %\r
Date: Mon, 26 Oct 2026 11:27:47 +0100\r
MIME-Version: 1.0\r
Content-Type: multipart/alternative; boundary="b"\r
\r
--b\r
Content-Type: text/html; charset=utf-8\r
\r
<html xmlns="http://www.w3.org/1999/xhtml"><head>\r
<link rel="stylesheet" href="https://cdn.example.net/x.css"></head><body>\r
<img src="https://tracker.example.org/p.gif">\r
<a href="https://win.casino-promo.site/play?uid=1">Jouer</a>\r
<a href="mailto:x@y.com">mail</a> <a href="javascript:alert(1)">js</a>\r
</body></html>\r
--b--\r
"""


@pytest.fixture
def spam_message() -> EmailMessage:
    return parse_message(RAW_SPAM)


@pytest.fixture
def unauthenticated_message() -> EmailMessage:
    return parse_message(RAW_UNAUTHENTICATED)


def make_sample(raw: bytes = RAW_SPAM, graph_id: str = "id") -> Sample:
    return Sample.from_raw(graph_id, raw)


@pytest.fixture
def samples() -> list[Sample]:
    return [make_sample(RAW_SPAM, "id-1"),
            make_sample(RAW_UNAUTHENTICATED, "id-2")]


class FakeRdap:
    """RDAP client answering from a dictionary, recording its calls."""

    def __init__(self, answers: dict[str, AbuseLookup]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def lookup(self, target: str) -> AbuseLookup:
        self.calls.append(target)
        return self.answers.get(target, AbuseLookup(target))


#: RDAP answers matching the two messages above.
RDAP_ANSWERS = {
    "93.184.215.14": AbuseLookup("93.184.215.14", "93.184.215.14",
                                 "Edgecast", ("abuse@edgecast.test",)),
    "20.12.182.63": AbuseLookup("20.12.182.63", "20.12.182.63",
                                "Microsoft Corporation",
                                ("abuse@microsoft.com",)),
    "spam-sender.com": AbuseLookup("spam-sender.com", "spam-sender.com",
                                   "Cheap Registrar",
                                   ("abuse@registrar.test",)),
    "bounces.spam-sender.com": AbuseLookup(
        "bounces.spam-sender.com", "spam-sender.com", "Cheap Registrar",
        ("abuse@registrar.test",)),
    "login.phish-site.com": AbuseLookup(
        "login.phish-site.com", "phish-site.com", "Cheap Registrar",
        ("abuse@registrar.test",)),
    "win.casino-promo.site": AbuseLookup(
        "win.casino-promo.site", "casino-promo.site", "Other Registrar",
        ("abuse@other-registrar.test",)),
    "104.16.1.1": AbuseLookup("104.16.1.1", "104.16.1.1", "Cloudflare, Inc.",
                              ("abuse@cloudflare.com",)),
}


@pytest.fixture
def fake_rdap() -> FakeRdap:
    return FakeRdap(dict(RDAP_ANSWERS))


def fake_resolver(domain: str) -> list[str]:
    """Every advertised site is behind Cloudflare."""
    return ["104.16.1.1"]


def empty_mailbox_mock() -> mock.Mock:
    """A mocked :class:`GraphMailClient` with no sent report, no reply."""
    client = mock.Mock()
    client.list_sent_conversations.return_value = {}
    client.list_replies.return_value = []
    return client


@pytest.fixture
def graph_client() -> mock.Mock:
    """A mocked :class:`GraphMailClient`."""
    return empty_mailbox_mock()
