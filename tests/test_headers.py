"""Tests for the evidence extraction (headers and links)."""

import pytest

from counter_spam.headers import (MAX_LINKS_PER_MESSAGE, SpamEvidence,
                                  collect_evidence, defang, extract_links,
                                  header_text, normalise_domain,
                                  normalise_public_ip, parse_message)


class TestAuthenticatedMessage:
    def test_decodes_encoded_headers(self, spam_message):
        evidence = collect_evidence(spam_message)
        assert evidence.subject == "Votre compte est bloqué"
        assert evidence.sender == "PayPal Sécurité <security@paypal.com>"
        assert evidence.date == "Sat, 31 Oct 2026 10:00:00 +0000"
        assert evidence.message_id == "<abc@spam-sender.com>"

    def test_sending_ip_is_extracted_once(self, spam_message):
        assert collect_evidence(spam_message).sender_ips == ["93.184.215.14"]

    def test_spf_and_dkim_pass_make_domains_verified(self, spam_message):
        evidence = collect_evidence(spam_message)
        assert evidence.verified_domains == ["spam-sender.com",
                                             "bounces.spam-sender.com"]

    def test_helo_is_never_verified(self, spam_message):
        evidence = collect_evidence(spam_message)
        assert "mail.spam-sender.com" in evidence.unverified_domains
        assert "mail.spam-sender.com" not in evidence.verified_domains

    def test_spoofed_from_domain_is_ignored(self, spam_message):
        evidence = collect_evidence(spam_message)
        everything = (evidence.verified_domains
                      + evidence.unverified_domains + evidence.sender_ips)
        assert "paypal.com" not in everything

    def test_declared_abuse_contact(self, spam_message):
        evidence = collect_evidence(spam_message)
        assert evidence.declared_abuse_contacts == ["abuse@spam-sender.com"]

    def test_plain_text_links(self, spam_message):
        evidence = collect_evidence(spam_message)
        assert evidence.links == ["https://login.phish-site.com/verify?id=42"]
        assert evidence.link_hosts == ["login.phish-site.com"]

    def test_primary_domain_prefers_verified_domain(self, spam_message):
        assert collect_evidence(spam_message).primary_domain == \
            "spam-sender.com"


class TestUnauthenticatedMessage:
    def test_failed_checks_leave_domains_unverified(
            self, unauthenticated_message):
        evidence = collect_evidence(unauthenticated_message)
        assert evidence.verified_domains == []
        assert set(evidence.unverified_domains) == {
            "webassembly.github.io", "forged.example", "forged-dkim.example"}

    def test_primary_domain_falls_back_to_ip(self, unauthenticated_message):
        assert collect_evidence(unauthenticated_message).primary_domain == \
            "20.12.182.63"

    def test_only_anchor_links_are_kept(self, unauthenticated_message):
        # Stylesheets, images, XML namespaces, mailto and javascript links
        # are not the spammer's site and must not be reported.
        assert collect_evidence(unauthenticated_message).links == \
            ["https://win.casino-promo.site/play?uid=1"]


class TestLinks:
    def _message(self, body: str, subtype: str = "plain") -> bytes:
        return (f"Content-Type: text/{subtype}; charset=utf-8\r\n\r\n"
                f"{body}").encode()

    def test_links_are_deduplicated_and_trailing_punctuation_dropped(self):
        raw = self._message("See https://a.example.com/x. Again "
                            "https://a.example.com/x, end")
        assert extract_links(parse_message(raw)) == \
            ["https://a.example.com/x"]

    def test_link_count_is_capped(self):
        body = " ".join(f"https://site{i}.example.com/"
                        for i in range(MAX_LINKS_PER_MESSAGE + 5))
        links = extract_links(parse_message(self._message(body)))
        assert len(links) == MAX_LINKS_PER_MESSAGE

    def test_ip_literal_and_invalid_hosts_are_ignored(self):
        raw = self._message("http://1.2.3.4/x http://localhost/ "
                            "http://bad_host.example/ https://ok.example.org")
        assert extract_links(parse_message(raw)) == ["https://ok.example.org"]

    def test_attachments_are_not_scanned(self):
        raw = (b"MIME-Version: 1.0\r\n"
               b"Content-Type: multipart/mixed; boundary=z\r\n\r\n"
               b"--z\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
               b"--z\r\nContent-Type: text/plain\r\n"
               b"Content-Disposition: attachment; filename=a.txt\r\n\r\n"
               b"https://hidden.example.com/\r\n--z--\r\n")
        assert extract_links(parse_message(raw)) == []

    def test_undecodable_charset_does_not_crash(self):
        raw = (b"Content-Type: text/plain; charset=unknown-8bit-xyz\r\n\r\n"
               b"https://ok.example.com/ \xff\xfe")
        assert extract_links(parse_message(raw)) == \
            ["https://ok.example.com/"]

    def test_html_entities_in_href_are_decoded(self):
        raw = self._message('<a href="https://x.example.com/?a=1&amp;b=2">'
                            'go</a>', "html")
        assert extract_links(parse_message(raw)) == \
            ["https://x.example.com/?a=1&b=2"]


class TestEdgeCases:
    def test_message_without_headers(self):
        evidence = collect_evidence(parse_message(b"\r\nbody only"))
        assert evidence == SpamEvidence(subject="(no subject)")
        assert evidence.primary_domain == "unknown"

    def test_header_text_collapses_folding(self):
        message = parse_message(b"Subject: a\r\n  b\r\n\tc\r\n\r\n")
        assert header_text(message, "Subject") == "a b c"
        assert header_text(message, "Missing") == ""

    def test_private_ips_are_dropped(self):
        raw = (b"Authentication-Results: spf=pass (sender IP is 10.1.2.3)"
               b" smtp.mailfrom=a.example.com\r\n\r\n")
        assert collect_evidence(parse_message(raw)).sender_ips == []

    def test_ipv6_sender(self):
        raw = (b"Received-SPF: Pass client-ip=2a00:1450:4864::1; "
               b"helo=x.example.com;\r\n\r\n")
        assert collect_evidence(parse_message(raw)).sender_ips == \
            ["2a00:1450:4864::1"]


@pytest.mark.parametrize("value, expected", [
    ("Mail.Example.COM.", "mail.example.com"),
    ("user@example.org", "example.org"),
    ("<example.net>", "example.net"),
    ("-h evil.com", None),
    ("example.com;rm -rf", None),
    ("localhost", None),
    ("../../etc/passwd", None),
    ("a" * 64 + ".com", None),
    ("", None),
])
def test_normalise_domain(value, expected):
    assert normalise_domain(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("8.8.8.8", "8.8.8.8"),
    ("[2001:4860:4860::8888]", "2001:4860:4860::8888"),
    ("10.0.0.1", None),
    ("127.0.0.1", None),
    ("192.168.1.1", None),
    ("::1", None),
    ("not-an-ip", None),
])
def test_normalise_public_ip(value, expected):
    assert normalise_public_ip(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("https://evil.com/a.b", "hxxps://evil[.]com/a[.]b"),
    ("HTTP://x.org", "hxxp://x[.]org"),
    ("evil.com", "evil[.]com"),
])
def test_defang(value, expected):
    assert defang(value) == expected


def test_non_text_parts_are_not_scanned_for_links():
    raw = (b"MIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=z\r\n\r\n"
           b"--z\r\nContent-Type: text/calendar\r\n\r\n"
           b"URL:https://calendar.example.com/\r\n"
           b"--z\r\nContent-Type: image/svg+xml\r\n\r\n"
           b"<a href='https://svg.example.com/'>x</a>\r\n"
           b"--z\r\nContent-Type: text/plain\r\n\r\n"
           b"https://body.example.com/\r\n--z--\r\n")
    assert extract_links(parse_message(raw)) == ["https://body.example.com/"]


def test_undecodable_header_is_skipped(monkeypatch):
    message = parse_message(b"Subject: hello\r\n\r\n")

    class Broken:
        def __str__(self):
            raise LookupError("unknown charset")

    monkeypatch.setattr(message, "get_all",
                        lambda name, failobj=None: [Broken()])
    assert header_text(message, "Subject") == ""


def test_multiple_authentication_results_headers():
    raw = (b"Authentication-Results: spf=fail (sender IP is 8.8.8.8)"
           b" smtp.mailfrom=a.example.com\r\n"
           b"Authentication-Results: dkim=pass header.d=b.example.com\r\n"
           b"\r\n")
    evidence = collect_evidence(parse_message(raw))
    assert evidence.verified_domains == ["b.example.com"]
    assert evidence.unverified_domains == ["a.example.com"]
    assert evidence.sender_ips == ["8.8.8.8"]


def test_dkim_identity_with_local_part():
    raw = (b"Authentication-Results: dkim=pass header.i=@mail.example.com"
           b"\r\n\r\n")
    assert collect_evidence(parse_message(raw)).verified_domains == \
        ["mail.example.com"]


@pytest.mark.parametrize("result", ["fail", "none", "neutral", "softfail",
                                    "temperror", "permerror"])
def test_only_pass_counts_as_verified(result):
    raw = (f"Authentication-Results: spf={result} smtp.mailfrom="
           f"x.example.com; dkim={result} header.d=y.example.com\r\n\r\n"
           ).encode()
    assert collect_evidence(parse_message(raw)).verified_domains == []


def test_stdlib_parser_crash_falls_back_to_raw_value():
    # Found by fuzzing: this From header makes the standard library raise
    # AttributeError ('Group' object has no attribute 'local_part').
    raw = b"From: a:b;c\r\nSubject: ok\r\n\r\nbody"
    message = parse_message(raw)
    try:
        message.get_all("From")
        crashes = False
    except AttributeError:
        crashes = True
    evidence = collect_evidence(message)
    assert evidence.subject == "ok"
    if crashes:
        assert evidence.sender == "a:b;c"


def test_any_header_parsing_error_is_contained(monkeypatch):
    message = parse_message(b"From: x@y.z\r\nSubject: s\r\n\r\n")

    def broken(name, failobj=None):
        raise AttributeError("stdlib bug")

    monkeypatch.setattr(message, "get_all", broken)
    assert header_text(message, "From") == "x@y.z"


def test_malformed_ipv6_link_is_ignored():
    # Found by fuzzing: urlsplit() raises "Invalid IPv6 URL".
    raw = (b"Content-Type: text/plain\r\n\r\n"
           b"https://[abc/x https://ok.example.com/")
    evidence = collect_evidence(parse_message(raw))
    assert evidence.links == ["https://ok.example.com/"]
    assert evidence.link_hosts == ["ok.example.com"]


def test_garbage_content_type_does_not_break_parsing():
    # Found by fuzzing: the stdlib parser raises IndexError on this header.
    raw = (b"Content-Type: \x1c\xa7\xb9u$ *\xe1;\x97\xfe*\r\n"
           b"Subject: still readable\r\n"
           b"Authentication-Results: spf=pass (sender IP is 8.8.8.8)"
           b" smtp.mailfrom=a.example.com\r\n\r\n"
           b"https://site.example.com/")
    evidence = collect_evidence(parse_message(raw))
    assert evidence.subject == "still readable"
    assert evidence.sender_ips == ["8.8.8.8"]
    assert evidence.verified_domains == ["a.example.com"]


def test_parser_last_resort(monkeypatch):
    from counter_spam import headers

    real = headers.BytesParser.parsebytes
    full_parses = []

    def flaky(self, raw, headersonly=False):
        # The two first full parses fail like the stdlib bug does; the
        # lenient header split (headersonly) keeps working.
        if not headersonly:
            full_parses.append(raw)
            if len(full_parses) < 3:
                raise IndexError("stdlib bug")
        return real(self, raw, headersonly)

    monkeypatch.setattr(headers.BytesParser, "parsebytes", flaky)
    message = parse_message(b"Subject: x\r\n\r\nhello body")
    assert len(full_parses) == 3
    assert message.get_content().strip() == "hello body"


def test_parser_gives_up_gracefully(monkeypatch):
    from counter_spam import headers

    def broken(self, raw, headersonly=False):
        raise IndexError("stdlib bug")

    monkeypatch.setattr(headers, "_split_headers", lambda raw: ([], b"x"))
    monkeypatch.setattr(headers.BytesParser, "parsebytes", broken)
    message = parse_message(b"anything")
    assert collect_evidence(message).subject == "(no subject)"
