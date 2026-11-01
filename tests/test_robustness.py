"""Robustness: hostile or malformed spam must never crash the analysis.

Spam is attacker-controlled input.  These tests feed thousands of
deterministically mutated messages to the whole analysis pipeline and
check its invariants.
"""

import random
import unicodedata

import pytest

from conftest import RAW_SPAM, RAW_UNAUTHENTICATED
from counter_spam.campaign import ReportGroup, SENDING_SERVER, Finding, \
    Sample
from counter_spam.display import message_text, sanitize
from counter_spam.headers import (collect_evidence, normalise_domain,
                                  normalise_public_ip, parse_message)
from counter_spam.report import build_group_report

SEEDS = range(1000)


def mutate(raw: bytes, rng: random.Random) -> bytes:
    """Return a randomly damaged copy of *raw*."""
    data = bytearray(raw)
    for _ in range(rng.randint(1, 20)):
        operation = rng.choice(("flip", "insert", "delete", "truncate",
                                "garbage-header"))
        position = rng.randrange(len(data) or 1)
        if operation == "flip" and data:
            data[position] = rng.randrange(256)
        elif operation == "insert":
            data[position:position] = bytes(rng.randrange(256)
                                            for _ in range(rng.randint(1, 8)))
        elif operation == "delete" and data:
            del data[position:position + rng.randint(1, 16)]
        elif operation == "truncate":
            del data[position:]
        else:
            header = rng.choice((b"Authentication-Results", b"Received-SPF",
                                 b"Subject", b"From", b"Content-Type",
                                 b"DKIM-Signature", b"X-Report-Abuse-To"))
            junk = bytes(rng.randrange(1, 256) for _ in range(40))
            data[0:0] = header + b": " + junk.replace(b"\n", b" ") + b"\r\n"
    return bytes(data)


def _is_clean(text: str) -> bool:
    return all(char in "\n\t"
               or not unicodedata.category(char).startswith("C")
               for char in text)


@pytest.mark.parametrize("seed", SEEDS)
def test_mutated_messages_never_crash(seed):
    rng = random.Random(seed)
    raw = mutate(rng.choice((RAW_SPAM, RAW_UNAUTHENTICATED)), rng)

    message = parse_message(raw)
    evidence = collect_evidence(message)
    text = message_text(message)

    # Everything used for network lookups is strictly validated.
    for domain in evidence.verified_domains + evidence.unverified_domains:
        assert normalise_domain(domain) == domain
    for ip in evidence.sender_ips:
        assert normalise_public_ip(ip) == ip
    for host in evidence.link_hosts:
        assert normalise_domain(host) == host
    # What reaches the terminal holds no control characters.
    assert _is_clean(text)

    # The report can always be built and stays single-line per field.
    group = ReportGroup(email="abuse@test.example")
    group.add(0, Finding(SENDING_SERVER, "8.8.8.8"))
    parts = build_group_report(group, [Sample("id", raw, evidence)])
    for part in parts:
        assert "\r" not in part.subject and "\n" not in part.subject
        assert part.attachments[0][1] == raw


@pytest.mark.parametrize("payload", [
    b"",
    b"\r\n\r\n",
    b"\x00" * 1000,
    b"Subject: " + b"A" * 100_000 + b"\r\n\r\n",
    b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n" * 200,
    b"Content-Type: text/html\r\n\r\n" + b"<a href='" * 5000,
    b"Authentication-Results: " + b"spf=pass smtp.mailfrom=" * 2000 + b"\r\n",
])
def test_pathological_messages(payload):
    message = parse_message(payload)
    collect_evidence(message)
    message_text(message)


def test_header_injection_through_folded_subject():
    raw = (b"Subject: =?utf-8?q?Hello=0D=0ABcc=3A_victim=40example=2Ecom?=\r\n"
           b"\r\nbody")
    evidence = collect_evidence(parse_message(raw))
    group = ReportGroup(email="abuse@test.example")
    group.add(0, Finding(SENDING_SERVER, "8.8.8.8"))
    body = build_group_report(group, [Sample("id", raw, evidence)])[0].body
    line = next(line for line in body.splitlines() if "Hello" in line)
    assert "Bcc: victim@example.com" in line  # Kept on the same line.


@pytest.mark.parametrize("text", [
    "\x1b[2J\x1b[H",           # Clear screen
    "\x1b]0;pwned\x07",        # Set window title
    "\x9b31m",                 # 8-bit CSI
    "‮⁦⁩",      # Bidi controls
    "﻿‍",            # BOM / zero-width joiner
])
def test_sanitize_removes_terminal_attacks(text):
    assert not any(unicodedata.category(char).startswith("C")
                   for char in sanitize(text))
