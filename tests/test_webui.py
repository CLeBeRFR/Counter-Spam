"""Tests for the local web interface, through a real HTTP server."""

import http.client
import io
import json
import threading
import time
import zipfile
from unittest import mock

import pytest

from conftest import RAW_SPAM, RAW_UNAUTHENTICATED, \
    empty_mailbox_mock, fake_resolver
from counter_spam.campaign import CampaignPlanner, ReportLedger
from counter_spam.graph import MessageSummary
from counter_spam.webui import TOKEN_HEADER, CounterSpamApp, make_server

TOKEN = "test-token-0123456789"


@pytest.fixture
def graph_client():
    client = empty_mailbox_mock()
    client.list_junk_messages.return_value = [
        MessageSummary("m1", "s", "f", "d"),
        MessageSummary("m2", "s", "f", "d")]
    client.get_message_mime.side_effect = \
        lambda message_id: RAW_SPAM if message_id == "m1" \
        else RAW_UNAUTHENTICATED
    return client


@pytest.fixture
def app(fake_rdap, graph_client, monkeypatch):
    # No pause between sends during tests.
    monkeypatch.setattr("counter_spam.campaign.time.sleep", lambda _: None)
    authenticator = mock.Mock()
    authenticator.signed_in_username.return_value = "me@outlook.com"
    ledger = ReportLedger(None)
    scopes_seen = []

    def client_factory(scopes):
        scopes_seen.append(list(scopes))
        return graph_client

    application = CounterSpamApp(
        authenticator, ledger,
        planner_factory=lambda **options: CampaignPlanner(
            fake_rdap, resolve=fake_resolver, ledger=ledger, **options),
        client_factory=client_factory)
    application.scopes_seen = scopes_seen
    return application


@pytest.fixture
def server(app):
    httpd, url = make_server(app, token=TOKEN)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def request(server, method, path, *, body=None, token=TOKEN, host=None,
            content_type="application/json"):
    port = server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        headers[TOKEN_HEADER] = token
    payload = None
    if body is not None:
        payload = body if isinstance(body, bytes) else \
            json.dumps(body).encode()
        headers["Content-Type"] = content_type
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response, data


def wait_for(server, phases, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = json.loads(request(server, "GET", "/api/state")[1])
        if state["phase"] in phases:
            return state
        time.sleep(0.05)
    raise AssertionError(f"Timed out, last phase {state['phase']}")


def analysed(server):
    assert request(server, "POST", "/api/analyse",
                   body={"limit": 2})[0].status == 202
    return wait_for(server, {"ready", "error"})


class TestAccessControl:
    def test_page_requires_token_in_query(self, server):
        assert request(server, "GET", "/")[0].status == 403
        assert request(server, "GET", "/?t=wrong")[0].status == 403
        response, body = request(server, "GET", f"/?t={TOKEN}")
        assert response.status == 200
        assert b"<title>Counter-Spam</title>" in body

    def test_dns_rebinding_is_blocked(self, server):
        for path in ("/app.js", f"/?t={TOKEN}", "/api/state"):
            response, _ = request(server, "GET", path, host="evil.test:80")
            assert response.status == 403

    def test_localhost_host_is_accepted(self, server):
        port = server.server_address[1]
        response, _ = request(server, "GET", "/app.js",
                              host=f"localhost:{port}")
        assert response.status == 200

    def test_api_requires_token_header(self, server):
        assert request(server, "GET", "/api/state",
                       token=None)[0].status == 403
        assert request(server, "GET", "/api/state",
                       token="bad")[0].status == 403
        assert request(server, "POST", "/api/analyse", body={},
                       token=None)[0].status == 403

    def test_post_requires_json(self, server):
        response, _ = request(server, "POST", "/api/analyse", body=b"limit=1",
                              content_type="application/x-www-form-urlencoded")
        assert response.status == 415

    def test_body_size_is_limited(self, server):
        response, _ = request(server, "POST", "/api/send",
                              body=b"x" * (300 * 1024))
        assert response.status == 413

    def test_invalid_json(self, server):
        assert request(server, "POST", "/api/analyse",
                       body=b"{nope")[0].status == 400
        assert request(server, "POST", "/api/analyse",
                       body=b"[1]")[0].status == 400

    def test_unknown_routes(self, server):
        assert request(server, "GET", "/etc/passwd")[0].status == 404
        assert request(server, "POST", "/api/nope", body={})[0].status == 404

    def test_security_headers(self, server):
        response, _ = request(server, "GET", f"/?t={TOKEN}")
        csp = response.getheader("Content-Security-Policy")
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("Referrer-Policy") == "no-referrer"
        assert response.getheader("Cache-Control") == "no-store"

    def test_static_content_types(self, server):
        js, _ = request(server, "GET", "/app.js")
        css, _ = request(server, "GET", "/style.css")
        assert js.getheader("Content-Type").startswith("text/javascript")
        assert css.getheader("Content-Type").startswith("text/css")
        icon, body = request(server, "GET", "/icon.svg")
        assert icon.getheader("Content-Type") == "image/svg+xml"
        assert body.startswith(b"<svg")

    def test_server_listens_on_loopback_only(self, server):
        assert server.server_address[0] == "127.0.0.1"


class TestWorkflow:
    def test_initial_state(self, server):
        state = json.loads(request(server, "GET", "/api/state")[1])
        assert state["phase"] == "idle"
        assert state["account"] == "me@outlook.com"
        assert state["plan"] is None

    def test_analysis_uses_read_only_scope(self, server, app):
        state = analysed(server)
        assert state["phase"] == "ready"
        assert app.scopes_seen == [["Mail.Read"]]
        plan = state["plan"]
        assert plan["count"] == 2
        emails = [group["email"] for group in plan["groups"]]
        assert "abuse@microsoft.com" in emails
        microsoft = next(group for group in plan["groups"]
                         if group["email"] == "abuse@microsoft.com")
        assert microsoft["formUrl"] == \
            "https://msrc.microsoft.com/report/abuse"
        assert microsoft["messages"][0]["findings"] == [
            {"kind": "sending-server", "resource": "20.12.182.63",
             "via": ""}]
        assert microsoft["preview"].startswith("Dear Microsoft Corporation")

    def test_spam_content_is_sanitised_in_json(self, server):
        state = analysed(server)
        text = json.dumps(state)
        assert "\\u001b" not in text  # No escape sequences.

    def test_sending_selected_groups(self, server, app, graph_client):
        plan = analysed(server)["plan"]
        target = next(group for group in plan["groups"]
                      if group["email"] == "abuse@microsoft.com")
        response, _ = request(server, "POST", "/api/send", body={
            "groups": [target["id"]], "note": "Thanks", "delete": True})
        assert response.status == 202
        state = wait_for(server, {"done", "error"})

        assert state["results"] == [{
            "groupId": target["id"], "email": "abuse@microsoft.com",
            "part": 1, "parts": 1, "ok": True, "error": ""}]
        assert app.scopes_seen[-1] == ["Mail.ReadWrite", "Mail.Send"]
        graph_client.send_mail.assert_called_once()
        assert "Thanks" in graph_client.send_mail.call_args.args[2]
        graph_client.move_to_deleted_items.assert_called_once_with("m2")

    def test_sending_requires_a_plan(self, server):
        response, body = request(server, "POST", "/api/send",
                                 body={"groups": ["x"]})
        assert response.status == 409

    def test_sending_requires_a_valid_selection(self, server):
        analysed(server)
        assert request(server, "POST", "/api/send",
                       body={"groups": ["unknown"]})[0].status == 400
        assert request(server, "POST", "/api/send",
                       body={"groups": "notalist"})[0].status == 400

    def test_concurrent_operations_are_refused(self, server, app,
                                               graph_client):
        release = threading.Event()
        graph_client.list_junk_messages.side_effect = \
            lambda limit: release.wait(5) and []
        assert request(server, "POST", "/api/analyse",
                       body={})[0].status == 202
        assert request(server, "POST", "/api/analyse",
                       body={})[0].status == 409
        release.set()
        wait_for(server, {"ready"})

    def test_background_errors_are_shown(self, server, graph_client):
        graph_client.list_junk_messages.side_effect = RuntimeError("boom")
        request(server, "POST", "/api/analyse", body={})
        state = wait_for(server, {"error"})
        assert state["error"] == "boom"

    def test_limit_is_clamped(self, server, graph_client):
        request(server, "POST", "/api/analyse", body={"limit": 10 ** 9})
        wait_for(server, {"ready"})
        graph_client.list_junk_messages.assert_called_with(limit=500)

    def test_eml_archive(self, server):
        plan = analysed(server)["plan"]
        group = next(group for group in plan["groups"]
                     if group["email"] == "abuse@cloudflare.com")
        response, body = request(
            server, "GET", f"/api/eml?group={group['id']}&t={TOKEN}",
            token=None)
        assert response.status == 200
        assert response.getheader("Content-Type") == "application/zip"
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            assert archive.namelist() == ["spam-001.eml", "spam-002.eml"]
            assert archive.read("spam-001.eml") == RAW_SPAM

    def test_eml_archive_access_control(self, server):
        analysed(server)
        assert request(server, "GET", "/api/eml?group=x&t=bad",
                       token=None)[0].status == 403
        assert request(server, "GET", f"/api/eml?group=x&t={TOKEN}",
                       token=None)[0].status == 404

    def test_quit_stops_the_server(self, app):
        httpd, _ = make_server(app, token=TOKEN)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        response, _ = request(httpd, "POST", "/api/quit", body={})
        assert response.status == 200
        thread.join(timeout=5)
        assert not thread.is_alive()
        httpd.server_close()


def test_make_server_generates_random_tokens(app):
    first, first_url = make_server(app)
    second, second_url = make_server(app)
    try:
        assert first_url != second_url
        token = first_url.split("?t=")[1]
        assert len(token) >= 40
    finally:
        first.server_close()
        second.server_close()


class TestMoreAccessControl:
    def test_post_with_invalid_host(self, server):
        assert request(server, "POST", "/api/analyse", body={},
                       host="evil.test")[0].status == 403

    def test_invalid_content_length(self, server):
        port = server.server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.putrequest("POST", "/api/analyse", skip_host=True)
        connection.putheader("Host", f"127.0.0.1:{port}")
        connection.putheader(TOKEN_HEADER, TOKEN)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "abc")
        connection.endheaders()
        assert connection.getresponse().status == 413
        connection.close()

    def test_token_comparison_is_exact(self, server):
        assert request(server, "GET", "/api/state",
                       token=TOKEN + "x")[0].status == 403
        assert request(server, "GET", "/api/state",
                       token=TOKEN[:-1])[0].status == 403


def test_default_client_signs_in_with_requested_scopes(fake_rdap):
    authenticator = mock.Mock()
    app = CounterSpamApp(authenticator, ReportLedger(None))
    client = app._default_client(["Mail.Read"])
    authenticator.get_access_token.assert_called_once_with(["Mail.Read"])
    authenticator.token_provider.assert_called_once_with(["Mail.Read"])
    assert client is not None


def test_run_announces_url_and_opens_browser(app, monkeypatch):
    from counter_spam import webui

    opened, announced = [], []
    monkeypatch.setattr(webui.webbrowser, "open", opened.append)

    def fake_serve_forever(self):
        announced.append("served")

    monkeypatch.setattr(webui.ThreadingHTTPServer, "serve_forever",
                        fake_serve_forever)
    webui.run(app, announce=announced.append)
    assert opened and opened[0].startswith("http://127.0.0.1:")
    assert "?t=" in opened[0]
    assert announced[0].endswith(opened[0])
    assert announced[-1] == "served"


def test_run_without_browser(app, monkeypatch):
    from counter_spam import webui

    monkeypatch.setattr(webui.webbrowser, "open",
                        mock.Mock(side_effect=AssertionError("opened")))
    monkeypatch.setattr(webui.ThreadingHTTPServer, "serve_forever",
                        lambda self: None)
    webui.run(app, open_browser=False, announce=lambda _: None)


def test_progress_is_exposed_while_sending(server, graph_client):
    plan = analysed(server)["plan"]
    groups = [group["id"] for group in plan["groups"]
              if not group["optional"]]
    release = threading.Event()
    graph_client.send_mail.side_effect = lambda *args, **kwargs: \
        release.wait(5)
    request(server, "POST", "/api/send", body={"groups": groups})
    state = wait_for(server, {"sending"})
    deadline = time.monotonic() + 5
    while not state["progress"]["total"] and time.monotonic() < deadline:
        state = json.loads(request(server, "GET", "/api/state")[1])
    assert state["phase"] == "sending"
    assert state["progress"]["total"] == len(groups)
    assert state["progress"]["done"] == 0
    assert "@" in state["progress"]["label"]  # Current recipient.
    release.set()
    done = wait_for(server, {"done"})
    assert done["progress"]["done"] == done["progress"]["total"]
    assert all(result["ok"] for result in done["results"])


class TestMarkReported:
    def test_marking_records_and_hides_the_group(self, server, app):
        plan = analysed(server)["plan"]
        target = plan["groups"][0]
        response, body = request(server, "POST", "/api/mark",
                                 body={"groups": [target["id"]]})
        assert response.status == 200
        assert json.loads(body) == {"ok": True, "marked": 1}
        state = json.loads(request(server, "GET", "/api/state")[1])
        assert target["id"] not in [g["id"] for g in state["plan"]["groups"]]
        # The next analysis does not offer these spams again.
        again = analysed(server)["plan"]
        assert target["email"] not in [g["email"] for g in again["groups"]]

    def test_marking_requires_a_plan_and_a_valid_group(self, server):
        assert request(server, "POST", "/api/mark",
                       body={"groups": ["x"]})[0].status == 409
        analysed(server)
        assert request(server, "POST", "/api/mark",
                       body={"groups": ["x"]})[0].status == 400
        assert request(server, "POST", "/api/mark",
                       body={"groups": "x"})[0].status == 400


def test_learning_failure_does_not_block_analysis(server, graph_client):
    from counter_spam.graph import GraphError

    graph_client.list_sent_conversations.side_effect = GraphError(
        403, "ErrorAccessDenied", "denied")
    assert analysed(server)["phase"] == "ready"


def test_learned_policies_are_shown_and_applied(fake_rdap, graph_client,
                                                monkeypatch):
    from counter_spam.feedback import PolicyStore
    from counter_spam.graph import ReceivedMessage

    monkeypatch.setattr("counter_spam.campaign.time.sleep", lambda _: None)
    graph_client.list_sent_conversations.return_value = {
        "c1": ["abuse@microsoft.com"]}
    graph_client.list_replies.return_value = [ReceivedMessage(
        "r1", "c1", "abuse@microsoft.com", "Automatic reply", "d")]
    graph_client.get_message_text.return_value = \
        "This mailbox is not monitored. Use https://msrc.microsoft.com/x"
    authenticator = mock.Mock()
    authenticator.signed_in_username.return_value = "me@outlook.com"
    ledger = ReportLedger(None)
    application = CounterSpamApp(
        authenticator, ledger, policies=PolicyStore(None),
        planner_factory=lambda **options: CampaignPlanner(
            fake_rdap, resolve=fake_resolver, ledger=ledger, **options),
        client_factory=lambda scopes: graph_client)
    httpd, _ = make_server(application, token=TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        plan = analysed(httpd)["plan"]
        assert plan["learned"] == [{"email": "abuse@microsoft.com",
                                    "status": "form"}]
        microsoft = next(g for g in plan["groups"]
                         if g["email"] == "abuse@microsoft.com")
        assert microsoft["sendsEmail"] is False
        assert microsoft["formUrl"] == "https://msrc.microsoft.com/x"
        # Such a group can never be e-mailed.
        assert request(httpd, "POST", "/api/send",
                       body={"groups": [microsoft["id"]]})[0].status == 400
    finally:
        httpd.shutdown()
        httpd.server_close()


class TestAutofill:
    @pytest.fixture
    def filled(self, app, monkeypatch, tmp_path):
        """Replace the browser by a recorder."""
        from counter_spam import autofill

        calls = []
        monkeypatch.setattr(autofill, "upload_directory",
                            lambda: tmp_path / "upload")

        def fake_fill(driver, url, data, status, **kwargs):
            status("Waiting for the form…")
            calls.append((driver, url, data))
            return 5

        monkeypatch.setattr(autofill, "fill_form", fake_fill)
        app._open_browser = lambda: "DRIVER"
        app._authenticator.signed_in_name.return_value = "Marie Dupont"
        return calls

    def wait_autofill(self, server, group_id, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = json.loads(request(server, "GET", "/api/state")[1])
            job = state["autofill"].get(group_id)
            if job and job["state"] != "running":
                return job
            time.sleep(0.05)
        raise AssertionError("autofill did not finish")

    def test_fills_the_preferred_form_with_group_data(self, server, app,
                                                      filled):
        plan = analysed(server)["plan"]
        cloudflare = next(g for g in plan["groups"]
                          if g["email"] == "abuse@cloudflare.com")
        response, _ = request(server, "POST", "/api/autofill",
                              body={"group": cloudflare["id"]})
        assert response.status == 202
        job = self.wait_autofill(server, cloudflare["id"])
        assert job["state"] == "done"
        assert "submit it" in job["message"]

        driver, url, data = filled[0]
        assert (driver, url) == ("DRIVER", "https://abuse.cloudflare.com/")
        assert data.reporter_email == "me@outlook.com"
        assert data.reporter_name == "Marie Dupont"
        assert data.ips == ["104.16.1.1"]
        assert data.domains == ["phish-site.com", "casino-promo.site"]
        assert data.urls == ["https://login.phish-site.com/verify?id=42",
                             "https://win.casino-promo.site/play?uid=1"]
        assert data.first_seen.isoformat() == "2026-10-26T11:27:47+01:00"
        assert data.body.startswith("Dear Cloudflare, Inc. abuse team,")
        assert [path.read_bytes() for path in data.attachments] == \
            [RAW_SPAM, RAW_UNAUTHENTICATED]
        assert app._browsers == ["DRIVER"]

    def test_group_without_form_is_refused(self, server, filled):
        plan = analysed(server)["plan"]
        no_form = next(g for g in plan["groups"] if not g["formUrl"])
        assert request(server, "POST", "/api/autofill",
                       body={"group": no_form["id"]})[0].status == 400
        assert request(server, "POST", "/api/autofill",
                       body={"group": "unknown"})[0].status == 400

    def test_errors_are_reported(self, server, app, filled):
        from counter_spam.autofill import AutofillUnavailable

        def no_browser():
            raise AutofillUnavailable("No browser could be started")

        app._open_browser = no_browser
        plan = analysed(server)["plan"]
        target = next(g for g in plan["groups"] if g["formUrl"])
        request(server, "POST", "/api/autofill", body={"group": target["id"]})
        job = self.wait_autofill(server, target["id"])
        assert job == {"state": "error",
                       "message": "No browser could be started"}

    def test_one_fill_at_a_time_per_group(self, server, app, filled,
                                          monkeypatch):
        from counter_spam import autofill

        release = threading.Event()
        monkeypatch.setattr(autofill, "fill_form",
                            lambda *args, **kwargs: release.wait(5))
        plan = analysed(server)["plan"]
        target = next(g for g in plan["groups"] if g["formUrl"])
        body = {"group": target["id"]}
        assert request(server, "POST", "/api/autofill",
                       body=body)[0].status == 202
        assert request(server, "POST", "/api/autofill",
                       body=body)[0].status == 409
        release.set()
        self.wait_autofill(server, target["id"])
