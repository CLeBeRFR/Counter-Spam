"""Minimal Microsoft Graph client for the Outlook mailbox operations we need.

Microsoft Graph replaces IMAP/SMTP: Microsoft has retired basic
(password) authentication for those protocols, and Graph offers
fine-grained delegated permissions (``Mail.Read`` vs ``Mail.Send`` ...).

Security notes:

* The bearer token is only ever sent to :data:`GRAPH_BASE_URL`.  Paging
  links returned by the server are checked before being followed so that
  a forged ``@odata.nextLink`` cannot leak the token to another host.
* Every request has a timeout and TLS certificate verification stays on
  (the ``requests`` default).
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence
from urllib.parse import quote

import requests

log = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

#: Well-known folder name: works whatever the mailbox language is
#: ("Junk", "Courrier indésirable", ...).
JUNK_FOLDER = "junkemail"
DELETED_ITEMS_FOLDER = "deleteditems"
SENT_ITEMS_FOLDER = "sentitems"

#: ``sendMail`` rejects requests whose (base64-encoded) attachments reach
#: 3 MB; larger content would need an upload session.
MAX_INLINE_ATTACHMENT_BYTES = 3 * 1024 * 1024

_RETRYABLE_STATUSES = frozenset({429, 503, 504})
_MAX_RETRIES = 3
_MAX_PAGE_SIZE = 50


class GraphError(RuntimeError):
    """Raised when Microsoft Graph returns an error response."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"Graph API error {status} ({code}): {message}")
        self.status = status
        self.code = code


@dataclass(frozen=True)
class MessageSummary:
    """Lightweight description of a message, as listed in a folder."""

    id: str
    subject: str
    sender: str
    received: str


@dataclass(frozen=True)
class ReceivedMessage:
    """A message received in reply to one of our reports."""

    id: str
    conversation_id: str
    sender: str
    subject: str
    received: str


class GraphMailClient:
    """Access the signed-in user's mailbox through Microsoft Graph.

    Args:
        token_provider: callable returning a valid access token; it is
            invoked for every request so that expired tokens get refreshed.
        timeout: per-request timeout, in seconds.
        session: optional :class:`requests.Session` (useful for tests).
    """

    def __init__(self, token_provider: Callable[[], str], *,
                 timeout: float = 30.0,
                 session: requests.Session | None = None) -> None:
        self._token_provider = token_provider
        self._timeout = timeout
        self._session = session or requests.Session()

    # -- public API -------------------------------------------------------

    def list_junk_messages(self, limit: int = 25) -> list[MessageSummary]:
        """Return the *limit* most recent messages of the Junk folder."""
        if limit < 1:
            return []
        url = (f"{GRAPH_BASE_URL}/me/mailFolders/{JUNK_FOLDER}/messages"
               f"?$select=id,subject,from,receivedDateTime"
               f"&$orderby=receivedDateTime%20desc"
               f"&$top={min(limit, _MAX_PAGE_SIZE)}")
        messages = []
        for item in self._paginate(url):
            messages.append(_summary_from_json(item))
            if len(messages) >= limit:
                break
        return messages

    def get_message_mime(self, message_id: str) -> bytes:
        """Return the raw RFC 822 content (headers included) of a message."""
        url = f"{GRAPH_BASE_URL}/me/messages/{_quote_id(message_id)}/$value"
        return self._request("GET", url).content

    def send_mail(self, recipients: Sequence[str], subject: str, body: str,
                  attachments: Sequence[tuple[str, bytes]] = ()) -> None:
        """Send a plain-text e-mail with optional ``.eml`` attachments.

        The message is saved in *Sent Items* so the user keeps a trace of
        every report sent on their behalf.

        Args:
            recipients: destination addresses.
            subject: subject line.
            body: plain-text body.
            attachments: ``(file name, raw RFC 822 bytes)`` pairs, attached
                as ``message/rfc822`` so abuse desks get full headers.

        Raises:
            ValueError: if there is no recipient or the attachments are
                too large to be sent inline.
        """
        if not recipients:
            raise ValueError("At least one recipient is required.")
        encoded = [(name, base64.b64encode(content).decode("ascii"))
                   for name, content in attachments]
        size = sum(len(content) for _, content in encoded)
        if size >= MAX_INLINE_ATTACHMENT_BYTES:
            raise ValueError(f"Attachments too large for sendMail "
                             f"({size} bytes once encoded).")
        message = {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": [{"emailAddress": {"address": address}}
                             for address in recipients],
        }
        if encoded:
            message["attachments"] = [{
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": name,
                "contentType": "message/rfc822",
                "contentBytes": content,
            } for name, content in encoded]
        self._request("POST", f"{GRAPH_BASE_URL}/me/sendMail",
                      json={"message": message, "saveToSentItems": True})

    def list_sent_conversations(self, subject_prefix: str,
                                limit: int = 200) -> dict[str, list[str]]:
        """Map the conversation of each sent message to its recipients.

        Only messages whose subject starts with *subject_prefix* are kept
        (the filtering is done locally: it works on every mailbox type).
        """
        url = (f"{GRAPH_BASE_URL}/me/mailFolders/{SENT_ITEMS_FOLDER}/messages"
               "?$select=subject,toRecipients,conversationId"
               f"&$orderby=sentDateTime%20desc&$top={_MAX_PAGE_SIZE}")
        conversations: dict[str, list[str]] = {}
        for count, item in enumerate(self._paginate(url), 1):
            if (item.get("subject") or "").startswith(subject_prefix) and \
                    item.get("conversationId"):
                conversations[item["conversationId"]] = [
                    recipient["emailAddress"]["address"].lower()
                    for recipient in item.get("toRecipients") or []
                    if recipient.get("emailAddress", {}).get("address")]
            if count >= limit:
                break
        return conversations

    def list_replies(self, conversation_ids: set[str],
                     limit: int = 300) -> list[ReceivedMessage]:
        """Return the received messages belonging to *conversation_ids*.

        Every folder is searched (replies are often moved to Junk or
        deleted), except *Sent Items* which holds our own messages.
        """
        if not conversation_ids:
            return []
        sent_folder = self._request(
            "GET", f"{GRAPH_BASE_URL}/me/mailFolders/{SENT_ITEMS_FOLDER}"
            "?$select=id").json().get("id")
        url = (f"{GRAPH_BASE_URL}/me/messages"
               "?$select=subject,from,conversationId,receivedDateTime,"
               "parentFolderId"
               f"&$orderby=receivedDateTime%20desc&$top={_MAX_PAGE_SIZE}")
        replies = []
        for count, item in enumerate(self._paginate(url), 1):
            if item.get("conversationId") in conversation_ids and \
                    item.get("parentFolderId") != sent_folder:
                address = (item.get("from") or {}).get("emailAddress") or {}
                replies.append(ReceivedMessage(
                    id=item["id"], conversation_id=item["conversationId"],
                    sender=(address.get("address") or "").lower(),
                    subject=item.get("subject") or "",
                    received=item.get("receivedDateTime", "")))
            if count >= limit:
                break
        return replies

    def get_message_text(self, message_id: str) -> str:
        """Return the body of a message, converted to text by Outlook."""
        url = (f"{GRAPH_BASE_URL}/me/messages/{_quote_id(message_id)}"
               "?$select=body")
        response = self._request(
            "GET", url, headers={"Prefer": 'outlook.body-content-type="text"'})
        return (response.json().get("body") or {}).get("content") or ""

    def move_to_deleted_items(self, message_id: str) -> None:
        """Move a message to *Deleted Items* (recoverable, not purged)."""
        url = f"{GRAPH_BASE_URL}/me/messages/{_quote_id(message_id)}/move"
        self._request("POST", url,
                      json={"destinationId": DELETED_ITEMS_FOLDER})

    # -- internals --------------------------------------------------------

    def _paginate(self, url: str) -> Iterator[dict]:
        """Yield every item of a paged Graph collection."""
        next_url: str | None = url
        while next_url:
            payload = self._request("GET", next_url).json()
            yield from payload.get("value", [])
            next_url = payload.get("@odata.nextLink")

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Send an authenticated request, retrying on throttling.

        Raises:
            ValueError: if *url* does not target Microsoft Graph.
            GraphError: on any non-success response.
        """
        if not url.startswith(GRAPH_BASE_URL + "/"):
            # Never send the bearer token anywhere else.
            raise ValueError(f"Refusing to send credentials to {url!r}")

        extra_headers = kwargs.pop("headers", {})
        for attempt in range(_MAX_RETRIES + 1):
            headers = {**extra_headers,
                       "Authorization": f"Bearer {self._token_provider()}"}
            response = self._session.request(
                method, url, headers=headers, timeout=self._timeout,
                allow_redirects=False, **kwargs)
            if (response.status_code not in _RETRYABLE_STATUSES
                    or attempt == _MAX_RETRIES):
                break
            delay = _retry_delay(response, attempt)
            log.info("Graph throttled the request (HTTP %s), retrying in "
                     "%.0f s", response.status_code, delay)
            time.sleep(delay)

        if not response.ok:
            raise _graph_error(response)
        return response


def _quote_id(message_id: str) -> str:
    """Percent-encode a message ID so it stays a single path segment."""
    if not message_id:
        raise ValueError("Empty message ID")
    return quote(message_id, safe="")


def _retry_delay(response: requests.Response, attempt: int) -> float:
    """Honour ``Retry-After`` if present, else use exponential backoff."""
    try:
        return min(float(response.headers["Retry-After"]), 60.0)
    except (KeyError, ValueError):
        return float(2 ** attempt)


def _graph_error(response: requests.Response) -> GraphError:
    """Build a :class:`GraphError` from an error response."""
    try:
        error = response.json().get("error", {})
    except ValueError:
        error = {}
    return GraphError(response.status_code,
                      error.get("code", "unknown"),
                      error.get("message", response.reason or ""))


def _summary_from_json(item: dict) -> MessageSummary:
    """Convert a Graph ``message`` resource into a :class:`MessageSummary`."""
    address = (item.get("from") or {}).get("emailAddress") or {}
    name, email = address.get("name", ""), address.get("address", "")
    sender = f"{name} <{email}>" if name and name != email else email
    return MessageSummary(id=item["id"],
                          subject=item.get("subject") or "(no subject)",
                          sender=sender or "(unknown sender)",
                          received=item.get("receivedDateTime", ""))
