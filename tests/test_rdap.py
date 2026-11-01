"""Tests for the RDAP abuse contact lookup (network mocked)."""

from unittest import mock

import pytest
import requests

from counter_spam.rdap import IANA_BOOTSTRAP_URLS, AbuseLookup, RdapClient

DNS_BOOTSTRAP = {"services": [
    [["com", "net"], ["https://rdap.example-registry.test/"]],
    [["uk"], ["http://insecure.test/"]],
    [["site"], ["https://rdap.site-registry.test/"]],
]}
IPV4_BOOTSTRAP = {"services": [
    [["93.0.0.0/8"], ["https://rdap.ripe.test/"]],
    [["93.184.0.0/16"], ["https://rdap.more-specific.test/"]],
]}
IPV6_BOOTSTRAP = {"services": [
    [["2a00::/12"], ["https://rdap.ripe.test/"]],
]}
DOMAIN_RECORD = {"ldhName": "EVIL.COM", "entities": [
    {"roles": ["registrant"],
     "vcardArray": ["vcard", [["email", {}, "text", "spammer@evil.com"]]]},
    {"roles": ["registrar"],
     "vcardArray": ["vcard", [["fn", {}, "text", "Cheap  Registrar"]]],
     "entities": [
         {"roles": ["abuse"],
          "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"],
                                   ["email", {}, "text", "Abuse@Reg.test"]]]},
     ]},
]}
IP_RECORD = {"name": "NET-93", "entities": [
    {"roles": ["abuse"],
     "vcardArray": ["vcard", [["email", {}, "text", "abuse@host.test"],
                              ["email", {}, "text", "abuse@host.test"]]]},
]}
# A registry answering for a sub-domain with the registered domain record.
SITE_RECORD = {"ldhName": "stepstudio.site", "entities": [
    {"roles": ["registrar", "abuse"],
     "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap"],
                              ["email", {}, "text", "abuse@nc.test"]]]},
]}


class FakeResponse:
    def __init__(self, status, payload=None, bad_json=False):
        self.status_code = status
        self.ok = status < 400
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("bad json")
        return self._payload


ROUTES = {
    IANA_BOOTSTRAP_URLS["dns"]: DNS_BOOTSTRAP,
    IANA_BOOTSTRAP_URLS["ipv4"]: IPV4_BOOTSTRAP,
    IANA_BOOTSTRAP_URLS["ipv6"]: IPV6_BOOTSTRAP,
    "https://rdap.example-registry.test/domain/evil.com": DOMAIN_RECORD,
    "https://rdap.more-specific.test/ip/93.184.215.14": IP_RECORD,
    "https://rdap.ripe.test/ip/2a00:1450::1": IP_RECORD,
    "https://rdap.site-registry.test/domain/ipoesf.stepstudio.site":
        SITE_RECORD,
}


@pytest.fixture
def session():
    fake = mock.Mock()
    fake.get.side_effect = lambda url, **_: (
        FakeResponse(200, ROUTES[url]) if url in ROUTES
        else FakeResponse(404))
    return fake


def queried(session):
    return [call.args[0] for call in session.get.call_args_list]


class TestDomains:
    def test_only_abuse_role_contacts_are_returned(self, session):
        assert RdapClient(session=session).abuse_contacts("evil.com") == \
            ["abuse@reg.test"]

    def test_lookup_reports_registrar_and_registered_name(self, session):
        result = RdapClient(session=session).lookup("evil.com")
        assert result == AbuseLookup("evil.com", "evil.com",
                                     "Cheap Registrar", ("abuse@reg.test",))

    def test_subdomains_fall_back_to_registered_domain(self, session):
        result = RdapClient(session=session).lookup("mx1.mail.evil.com")
        assert result.resource == "evil.com"
        assert queried(session)[-3:] == [
            "https://rdap.example-registry.test/domain/mx1.mail.evil.com",
            "https://rdap.example-registry.test/domain/mail.evil.com",
            "https://rdap.example-registry.test/domain/evil.com"]

    def test_registry_answering_for_subdomain_uses_ldh_name(self, session):
        result = RdapClient(session=session).lookup("ipoesf.stepstudio.site")
        assert result.resource == "stepstudio.site"
        assert result.organisation == "NameCheap"

    def test_plain_http_servers_are_never_queried(self, session):
        assert RdapClient(session=session).abuse_contacts("evil.co.uk") == []
        assert not any(url.startswith("http://")
                       for url in queried(session))

    def test_unknown_tld(self, session):
        assert RdapClient(session=session).lookup("x.unknowntld") == \
            AbuseLookup("x.unknowntld")

    def test_invalid_domain_is_not_queried(self, session):
        assert RdapClient(session=session).lookup("-h evil") == \
            AbuseLookup("-h evil")
        session.get.assert_not_called()

    def test_bootstrap_is_downloaded_once(self, session):
        client = RdapClient(session=session)
        client.lookup("evil.com")
        client.lookup("other.net")
        assert queried(session).count(IANA_BOOTSTRAP_URLS["dns"]) == 1


class TestIpAddresses:
    def test_longest_prefix_wins(self, session):
        result = RdapClient(session=session).lookup("93.184.215.14")
        assert result == AbuseLookup("93.184.215.14", "93.184.215.14",
                                     "NET-93", ("abuse@host.test",))

    def test_ipv6(self, session):
        assert RdapClient(session=session).abuse_contacts("2a00:1450::1") == \
            ["abuse@host.test"]

    def test_unallocated_ip(self, session):
        assert RdapClient(session=session).lookup("8.8.8.8").emails == ()


class TestFailures:
    def test_network_errors_yield_empty_results(self):
        session = mock.Mock()
        session.get.side_effect = requests.ConnectionError("down")
        assert RdapClient(session=session).lookup("evil.com").emails == ()

    def test_server_errors_and_bad_json_are_tolerated(self):
        session = mock.Mock()
        session.get.side_effect = lambda url, **_: (
            FakeResponse(200, DNS_BOOTSTRAP)
            if url == IANA_BOOTSTRAP_URLS["dns"]
            else FakeResponse(500) if "evil.com" in url
            else FakeResponse(200, bad_json=True))
        client = RdapClient(session=session)
        assert client.lookup("evil.com").emails == ()
        assert client.lookup("other.net").emails == ()

    def test_malformed_vcards_are_ignored(self):
        record = {"entities": [
            {"roles": ["abuse"], "vcardArray": "garbage"},
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email"], 42]]},
            {"roles": ["abuse"], "vcardArray": ["vcard", [
                ["email", {}, "text", "no-at-sign"]]]},
            "not-an-entity",
        ]}
        session = mock.Mock()
        session.get.side_effect = lambda url, **_: FakeResponse(
            200, DNS_BOOTSTRAP if url == IANA_BOOTSTRAP_URLS["dns"]
            else record)
        assert RdapClient(session=session).lookup("evil.com").emails == ()

    def test_requests_have_a_timeout(self, session):
        RdapClient(session=session, timeout=3).lookup("evil.com")
        assert all(call.kwargs["timeout"] == 3
                   for call in session.get.call_args_list)


class TestMoreLookups:
    def test_ip_without_record(self):
        session = mock.Mock()
        session.get.side_effect = lambda url, **_: (
            FakeResponse(200, IPV4_BOOTSTRAP)
            if url == IANA_BOOTSTRAP_URLS["ipv4"] else FakeResponse(404))
        assert RdapClient(session=session).lookup("93.184.215.14") == \
            AbuseLookup("93.184.215.14")

    def test_organisation_falls_back_to_record_name_or_nothing(self):
        session = mock.Mock()
        records = {
            "https://rdap.ripe.test/ip/93.1.1.1": {"entities": [
                {"roles": ["abuse"], "vcardArray": ["vcard", [
                    ["email", {}, "text", "a@b.test"]]]}]},
        }
        session.get.side_effect = lambda url, **_: (
            FakeResponse(200, IPV4_BOOTSTRAP)
            if url == IANA_BOOTSTRAP_URLS["ipv4"]
            else FakeResponse(200, records[url]) if url in records
            else FakeResponse(404))
        result = RdapClient(session=session).lookup("93.1.1.1")
        assert result.organisation == ""
        assert result.emails == ("a@b.test",)

    def test_second_server_is_tried_when_first_fails(self):
        bootstrap = {"services": [[["com"], [
            "https://down.test/", "https://up.test/"]]]}
        session = mock.Mock()
        session.get.side_effect = lambda url, **_: (
            FakeResponse(200, bootstrap)
            if url == IANA_BOOTSTRAP_URLS["dns"]
            else FakeResponse(503) if url.startswith("https://down.test")
            else FakeResponse(200, DOMAIN_RECORD))
        assert RdapClient(session=session).abuse_contacts("evil.com") == \
            ["abuse@reg.test"]

    def test_ldh_name_from_another_domain_is_ignored(self):
        record = dict(DOMAIN_RECORD, ldhName="attacker.com")
        session = mock.Mock()
        session.get.side_effect = lambda url, **_: FakeResponse(
            200, DNS_BOOTSTRAP if url == IANA_BOOTSTRAP_URLS["dns"]
            else record)
        assert RdapClient(session=session).lookup("evil.com").resource == \
            "evil.com"
