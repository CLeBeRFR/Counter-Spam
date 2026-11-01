"""End-to-end scenario: the real modules wired together, HTTP faked.

Only the transport is replaced: Microsoft Graph and RDAP servers answer
from in-memory routes, so the whole chain (CLI -> Graph client -> parsing
-> RDAP -> grouping -> report -> sendMail payload -> ledger) is exercised.
"""

import base64
import json
from unittest import mock

import pytest

from conftest import RAW_SPAM, RAW_UNAUTHENTICATED
from counter_spam import cli, config, graph
from counter_spam.graph import GraphMailClient
from counter_spam.rdap import IANA_BOOTSTRAP_URLS, RdapClient

GRAPH = graph.GRAPH_BASE_URL

RDAP_ROUTES = {
    IANA_BOOTSTRAP_URLS["dns"]: {"services": [
        [["com"], ["https://rdap.com.test/"]],
        [["site"], ["https://rdap.site.test/"]]]},
    IANA_BOOTSTRAP_URLS["ipv4"]: {"services": [
        [["20.0.0.0/8"], ["https://rdap.arin.test/"]],
        [["93.0.0.0/8"], ["https://rdap.ripe.test/"]],
        [["104.0.0.0/8"], ["https://rdap.arin.test/"]]]},
    "https://rdap.arin.test/ip/20.12.182.63": {"name": "MSFT", "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "Microsoft Corporation"]]]},
        {"roles": ["abuse"], "vcardArray": ["vcard", [
            ["email", {}, "text", "abuse@microsoft.com"]]]}]},
    "https://rdap.arin.test/ip/104.16.1.1": {"entities": [
        {"roles": ["registrant", "abuse"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "Cloudflare, Inc."],
            ["email", {}, "text", "abuse@cloudflare.com"]]]}]},
    "https://rdap.ripe.test/ip/93.184.215.14": {"entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [
            ["email", {}, "text", "abuse@edgecast.test"]]]}]},
    "https://rdap.com.test/domain/spam-sender.com": {
        "ldhName": "spam-sender.com", "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "Cheap Registrar"]]], "entities": [
                {"roles": ["abuse"], "vcardArray": ["vcard", [
                    ["email", {}, "text", "abuse@registrar.test"]]]}]}]},
}
RDAP_ROUTES["https://rdap.com.test/domain/phish-site.com"] = \
    RDAP_ROUTES["https://rdap.com.test/domain/spam-sender.com"] | {
        "ldhName": "phish-site.com"}
RDAP_ROUTES["https://rdap.site.test/domain/casino-promo.site"] = \
    RDAP_ROUTES["https://rdap.com.test/domain/spam-sender.com"] | {
        "ldhName": "casino-promo.site"}


class Response:
    def __init__(self, status=200, payload=None, content=b""):
        self.status_code = status
        self.ok = status < 400
        self.reason = ""
        self.headers = {}
        self._payload = payload
        self.content = content or json.dumps(payload or {}).encode()

    def json(self):
        return self._payload


class FakeGraph:
    """Minimal in-memory Microsoft Graph mailbox."""

    def __init__(self):
        self.messages = {"m1": RAW_SPAM, "m2": RAW_UNAUTHENTICATED}
        self.sent = []
        self.moved = []

    def request(self, method, url, headers=None, json=None, **kwargs):
        assert headers["Authorization"] == "Bearer ACCESS-TOKEN"
        assert url.startswith(GRAPH + "/")
        path = url[len(GRAPH):]
        if method == "GET" and path.startswith(
                "/me/mailFolders/junkemail/messages"):
            return Response(payload={"value": [
                {"id": key, "subject": "s", "receivedDateTime": "d",
                 "from": {"emailAddress": {"address": "x@y.z"}}}
                for key in self.messages]})
        if method == "GET" and path.endswith("/$value"):
            message_id = path.split("/")[3]
            return Response(content=self.messages[message_id])
        if method == "POST" and path == "/me/sendMail":
            self.sent.append(json)
            return Response(202)
        if method == "POST" and path.endswith("/move"):
            self.moved.append(path.split("/")[3])
            return Response(201, {"id": "new"})
        return Response(404, {"error": {"code": "NotFound", "message": ""}})


@pytest.fixture
def world(monkeypatch, tmp_path):
    mailbox = FakeGraph()
    rdap_session = mock.Mock()
    rdap_session.get.side_effect = lambda url, **_: (
        Response(200, RDAP_ROUTES[url]) if url in RDAP_ROUTES
        else Response(404))
    authenticator = mock.Mock()
    authenticator.get_access_token.return_value = "ACCESS-TOKEN"
    authenticator.token_provider.return_value = lambda: "ACCESS-TOKEN"
    authenticator.signed_in_username.return_value = "me@outlook.com"

    monkeypatch.setattr(config, "config_dir", lambda: tmp_path / "config")
    monkeypatch.setattr(cli, "cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(cli, "OutlookAuthenticator",
                        mock.Mock(return_value=authenticator))
    session = mock.Mock()
    session.request.side_effect = mailbox.request
    monkeypatch.setattr(cli, "GraphMailClient",
                        lambda provider: GraphMailClient(provider,
                                                         session=session))
    monkeypatch.setattr(cli, "RdapClient",
                        lambda: RdapClient(session=rdap_session))
    monkeypatch.setattr("counter_spam.campaign.resolve_addresses",
                        lambda domain: ["104.16.1.1"])
    monkeypatch.setattr("counter_spam.campaign.time.sleep", lambda _: None)
    return mailbox, tmp_path


def sent_to(mailbox):
    return {payload["message"]["toRecipients"][0]["emailAddress"]["address"]:
            payload for payload in mailbox.sent}


def test_full_report_flow(world):
    mailbox, tmp_path = world
    assert cli.main(["report", "--yes", "--delete"]) == 0

    reports = sent_to(mailbox)
    assert set(reports) == {"abuse@microsoft.com", "abuse@edgecast.test",
                            "abuse@registrar.test", "abuse@cloudflare.com"}

    # Microsoft gets the spam sent from its network, with the original.
    microsoft = reports["abuse@microsoft.com"]["message"]
    assert microsoft["subject"].startswith("Abuse report: 1 unsolicited")
    assert "sending server: 20.12.182.63" in microsoft["body"]["content"]
    assert microsoft["body"]["content"].startswith(
        "Dear Microsoft Corporation abuse team,")
    attachment = microsoft["attachments"][0]
    assert base64.b64decode(attachment["contentBytes"]) == \
        RAW_UNAUTHENTICATED

    # The registrar gets one report for both spams and both of its roles.
    registrar = reports["abuse@registrar.test"]["message"]
    body = registrar["body"]["content"]
    assert "authenticated sending domain: spam-sender.com" in body
    assert "domain advertised in the message: phish-site[.]com" in body
    assert "domain advertised in the message: casino-promo[.]site" in body
    assert len(registrar["attachments"]) == 2

    # Every report is kept in Sent Items; reported spams are moved.
    assert all(payload["saveToSentItems"] for payload in mailbox.sent)
    assert sorted(mailbox.moved) == ["m1", "m2"]

    # The ledger prevents a second report.
    ledger = json.loads((tmp_path / "cache" / "reported.json").read_text())
    assert len(ledger) == 2
    count = len(mailbox.sent)
    assert cli.main(["report", "--yes"]) == 0
    assert len(mailbox.sent) == count


def test_analyze_is_strictly_read_only(world, capsys):
    mailbox, tmp_path = world
    assert cli.main(["analyze"]) == 0
    assert mailbox.sent == [] and mailbox.moved == []
    assert not (tmp_path / "cache" / "reported.json").exists()
    output = capsys.readouterr().out
    # Four desks, plus the optional APWG group offered in the dry run.
    assert "5 abuse desk(s) concerned" in output
    assert "Anti-Phishing Working Group <reportphishing@apwg.org> " \
        "(optional)" in output
