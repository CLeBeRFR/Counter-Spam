"""Tests for the Microsoft Graph client (HTTP mocked)."""

import base64
from unittest import mock

import pytest

from counter_spam import graph
from counter_spam.graph import GraphError, GraphMailClient


class FakeResponse:
    def __init__(self, status=200, payload=None, content=b"", headers=None):
        self.status_code = status
        self.ok = status < 400
        self.reason = "reason"
        self.headers = headers or {}
        self.content = content
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload


def make_client(*responses, token="TOKEN"):
    session = mock.Mock()
    session.request.side_effect = list(responses)
    return GraphMailClient(lambda: token, session=session), session


def message(index, sender=None):
    return {"id": f"id{index}", "subject": f"s{index}",
            "from": sender if sender is not None else
            {"emailAddress": {"name": "N", "address": "a@b.c"}},
            "receivedDateTime": "2026-10-31T10:00:00Z"}


class TestListing:
    def test_follows_pagination_up_to_limit(self):
        next_link = graph.GRAPH_BASE_URL + "/me/next"
        client, session = make_client(
            FakeResponse(payload={"value": [message(1), message(2)],
                                  "@odata.nextLink": next_link}),
            FakeResponse(payload={"value": [message(3), message(4)]}))

        messages = client.list_junk_messages(limit=3)

        assert [m.id for m in messages] == ["id1", "id2", "id3"]
        first_url = session.request.call_args_list[0].args[1]
        assert "/mailFolders/junkemail/messages" in first_url
        assert "$top=3" in first_url

    def test_page_size_is_capped(self):
        client, session = make_client(FakeResponse(payload={"value": []}))
        client.list_junk_messages(limit=500)
        assert "$top=50" in session.request.call_args.args[1]

    def test_zero_limit_makes_no_request(self):
        client, session = make_client()
        assert client.list_junk_messages(limit=0) == []
        session.request.assert_not_called()

    @pytest.mark.parametrize("sender, expected", [
        ({"emailAddress": {"name": "N", "address": "a@b.c"}}, "N <a@b.c>"),
        ({"emailAddress": {"name": "a@b.c", "address": "a@b.c"}}, "a@b.c"),
        ({"emailAddress": {"address": "a@b.c"}}, "a@b.c"),
        ({}, "(unknown sender)"),
    ])
    def test_sender_formatting(self, sender, expected):
        client, _ = make_client(FakeResponse(
            payload={"value": [message(1, sender)]}))
        assert client.list_junk_messages()[0].sender == expected

    def test_missing_subject(self):
        item = message(1)
        item["subject"] = None
        client, _ = make_client(FakeResponse(payload={"value": [item]}))
        assert client.list_junk_messages()[0].subject == "(no subject)"


class TestSecurity:
    def test_token_is_never_sent_outside_graph(self):
        client, session = make_client(FakeResponse(payload={
            "value": [], "@odata.nextLink": "https://evil.test/steal"}))
        with pytest.raises(ValueError, match="Refusing"):
            client.list_junk_messages()
        assert session.request.call_count == 1

    def test_lookalike_host_is_refused(self):
        client, session = make_client(FakeResponse(payload={
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com.evil.test/x"}))
        with pytest.raises(ValueError):
            client.list_junk_messages()

    def test_message_id_cannot_escape_the_url_path(self):
        client, session = make_client(FakeResponse(content=b"raw"))
        client.get_message_mime("../../users/someone")
        url = session.request.call_args.args[1]
        assert url.endswith("/me/messages/..%2F..%2Fusers%2Fsomeone/$value")

    def test_empty_message_id_is_refused(self):
        client, _ = make_client()
        with pytest.raises(ValueError):
            client.get_message_mime("")

    def test_redirects_are_not_followed_and_timeout_set(self):
        client, session = make_client(FakeResponse(content=b"raw"))
        client.get_message_mime("id")
        kwargs = session.request.call_args.kwargs
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == 30.0
        assert kwargs["headers"] == {"Authorization": "Bearer TOKEN"}

    def test_errors_do_not_leak_the_token(self):
        client, _ = make_client(FakeResponse(
            403, payload={"error": {"code": "ErrorAccessDenied",
                                    "message": "Access is denied."}}))
        with pytest.raises(GraphError) as excinfo:
            client.get_message_mime("id")
        assert excinfo.value.status == 403
        assert excinfo.value.code == "ErrorAccessDenied"
        assert "TOKEN" not in str(excinfo.value)

    def test_non_json_error(self):
        client, _ = make_client(FakeResponse(502))
        with pytest.raises(GraphError, match="unknown"):
            client.get_message_mime("id")


class TestRetries:
    def test_throttled_requests_are_retried(self, monkeypatch):
        sleep = mock.Mock()
        monkeypatch.setattr(graph.time, "sleep", sleep)
        client, session = make_client(
            FakeResponse(429, headers={"Retry-After": "7"}),
            FakeResponse(content=b"raw"))
        assert client.get_message_mime("id") == b"raw"
        sleep.assert_called_once_with(7.0)

    def test_retry_delay_is_capped_and_has_backoff(self, monkeypatch):
        sleep = mock.Mock()
        monkeypatch.setattr(graph.time, "sleep", sleep)
        client, _ = make_client(
            FakeResponse(503, headers={"Retry-After": "9999"}),
            FakeResponse(504),
            FakeResponse(content=b"raw"))
        client.get_message_mime("id")
        assert [call.args[0] for call in sleep.call_args_list] == [60.0, 2.0]

    def test_gives_up_after_max_retries(self, monkeypatch):
        monkeypatch.setattr(graph.time, "sleep", lambda _: None)
        responses = [FakeResponse(429)] * (graph._MAX_RETRIES + 1)
        client, session = make_client(*responses)
        with pytest.raises(GraphError):
            client.get_message_mime("id")
        assert session.request.call_count == graph._MAX_RETRIES + 1

    def test_token_is_requested_for_each_attempt(self, monkeypatch):
        monkeypatch.setattr(graph.time, "sleep", lambda _: None)
        tokens = iter(["T1", "T2"])
        session = mock.Mock()
        session.request.side_effect = [FakeResponse(429),
                                       FakeResponse(content=b"x")]
        GraphMailClient(lambda: next(tokens), session=session) \
            .get_message_mime("id")
        sent = [call.kwargs["headers"]["Authorization"]
                for call in session.request.call_args_list]
        assert sent == ["Bearer T1", "Bearer T2"]


class TestSendMail:
    def test_attaches_the_original_messages(self):
        client, session = make_client(FakeResponse(202))
        client.send_mail(["abuse@reg.test", "abuse@other.test"], "subj",
                         "body", attachments=[("a.eml", b"raw1"),
                                              ("b.eml", b"raw2")])

        payload = session.request.call_args.kwargs["json"]
        assert payload["saveToSentItems"] is True
        message = payload["message"]
        assert message["body"] == {"contentType": "Text", "content": "body"}
        assert [r["emailAddress"]["address"]
                for r in message["toRecipients"]] == ["abuse@reg.test",
                                                      "abuse@other.test"]
        assert [(a["name"], a["contentType"],
                 base64.b64decode(a["contentBytes"]))
                for a in message["attachments"]] == [
            ("a.eml", "message/rfc822", b"raw1"),
            ("b.eml", "message/rfc822", b"raw2")]

    def test_without_attachments(self):
        client, session = make_client(FakeResponse(202))
        client.send_mail(["a@b.c"], "s", "b")
        assert "attachments" not in \
            session.request.call_args.kwargs["json"]["message"]

    def test_requires_a_recipient(self):
        client, session = make_client()
        with pytest.raises(ValueError):
            client.send_mail([], "s", "b")
        session.request.assert_not_called()

    def test_rejects_oversized_attachments(self):
        client, session = make_client()
        # 2.4 MB raw becomes 3.2 MB once base64-encoded (limit: 3 MiB).
        big = b"x" * 2_400_000
        with pytest.raises(ValueError, match="too large"):
            client.send_mail(["a@b.c"], "s", "b", [("a.eml", big)])
        session.request.assert_not_called()


def test_move_to_deleted_items():
    client, session = make_client(FakeResponse(201))
    client.move_to_deleted_items("id/1")
    method, url = session.request.call_args.args
    assert method == "POST"
    assert url.endswith("/me/messages/id%2F1/move")
    assert session.request.call_args.kwargs["json"] == \
        {"destinationId": "deleteditems"}


class TestReplies:
    def test_sent_conversations_keep_only_reports(self):
        client, session = make_client(FakeResponse(payload={"value": [
            {"subject": "Abuse report: 2 unsolicited", "conversationId": "c1",
             "toRecipients": [{"emailAddress": {"address": "Abuse@X.test"}}]},
            {"subject": "Hello", "conversationId": "c2",
             "toRecipients": [{"emailAddress": {"address": "a@b.test"}}]},
            {"subject": "Abuse report: 1", "conversationId": None,
             "toRecipients": []}]}))
        assert client.list_sent_conversations("Abuse report:") == \
            {"c1": ["abuse@x.test"]}
        assert "/mailFolders/sentitems/messages" in \
            session.request.call_args.args[1]

    def test_replies_exclude_sent_items(self):
        client, session = make_client(
            FakeResponse(payload={"id": "SENT"}),
            FakeResponse(payload={"value": [
                {"id": "r1", "conversationId": "c1", "parentFolderId": "INBOX",
                 "subject": "Auto-Reply", "receivedDateTime": "d",
                 "from": {"emailAddress": {"address": "Abuse@X.test"}}},
                {"id": "own", "conversationId": "c1",
                 "parentFolderId": "SENT", "subject": "Abuse report"},
                {"id": "other", "conversationId": "c9",
                 "parentFolderId": "INBOX", "subject": "x"}]}))
        replies = client.list_replies({"c1"})
        assert [(r.id, r.sender) for r in replies] == [("r1", "abuse@x.test")]

    def test_no_conversation_no_request(self):
        client, session = make_client()
        assert client.list_replies(set()) == []
        session.request.assert_not_called()

    def test_message_text_asks_outlook_for_plain_text(self):
        client, session = make_client(FakeResponse(payload={
            "body": {"contentType": "text", "content": "Use our form"}}))
        assert client.get_message_text("r/1") == "Use our form"
        kwargs = session.request.call_args.kwargs
        assert kwargs["headers"]["Prefer"] == \
            'outlook.body-content-type="text"'
        assert kwargs["headers"]["Authorization"] == "Bearer TOKEN"
        assert "/me/messages/r%2F1?$select=body" in \
            session.request.call_args.args[1]
