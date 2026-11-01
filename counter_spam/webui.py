"""Local web interface: review the grouped reports, then send them.

The interface is a small single-page application served by the Python
standard library and opened in the user's browser.  It works the same on
Windows, macOS and Linux.

Security design:

* the server listens on ``127.0.0.1`` only, on a random port;
* every API call must carry a random per-session token, sent in a custom
  header: other web sites cannot forge such requests (no CORS is
  answered), which defeats CSRF;
* the ``Host`` header is checked to defeat DNS rebinding;
* a strict Content-Security-Policy forbids inline scripts, remote content
  and framing; spam content is only ever inserted as text, never as HTML;
* abuse desk forms are opened in a new tab with ``noopener``; the
  interface never submits third-party forms itself.
"""

from __future__ import annotations

import hmac
import io
import json
import logging
import secrets
import threading
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from email.utils import parsedate_to_datetime

from . import autofill
from .auth import OutlookAuthenticator, required_scopes
from .campaign import LINK_DOMAIN, LINK_HOSTING, SENDING_DOMAIN, \
    CampaignPlan, CampaignPlanner, ReportGroup, ReportLedger, \
    fetch_samples, send_reports
from .headers import normalise_public_ip
from .display import sanitize
from .feedback import PolicyStore, learn_from_replies, policy_lookup
from .graph import GraphError, GraphMailClient
from .rdap import RdapClient
from .report import REPORT_SUBJECT_PREFIX, build_group_report

log = logging.getLogger(__name__)

TOKEN_HEADER = "X-Counter-Spam-Token"
MAX_BODY_BYTES = 256 * 1024
MAX_LIMIT = 500

_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class ConflictError(RuntimeError):
    """Raised when an action is requested while another one runs."""


class CounterSpamApp:
    """State and actions behind the web interface.

    Args:
        authenticator: signed-in authenticator.
        ledger: reports already sent.
        planner_factory: builds a :class:`CampaignPlanner` (for tests).
        client_factory: builds a Graph client for given scopes.
        policies: what the abuse desks' replies taught us.
    """

    def __init__(self, authenticator: OutlookAuthenticator,
                 ledger: ReportLedger, *,
                 policies: PolicyStore | None = None,
                 planner_factory: Callable[..., CampaignPlanner] | None = None,
                 client_factory: Callable[[list[str]], GraphMailClient]
                 | None = None) -> None:
        self._authenticator = authenticator
        self._ledger = ledger
        self._policies = policies or PolicyStore(None)
        self._learned: list[dict] = []
        self._planner_factory = planner_factory or (
            lambda **options: CampaignPlanner(RdapClient(), ledger=ledger,
                                              **options))
        self._client_factory = client_factory or self._default_client
        self._lock = threading.Lock()
        self._phase = "idle"
        self._progress = {"done": 0, "total": 0, "label": ""}
        self._error = ""
        self._plan: CampaignPlan | None = None
        self._plan_version = 0
        self._results: list[dict] = []
        self._autofill: dict[str, dict] = {}
        # Browser windows stay open (and driven) until the app exits.
        self._browsers: list = []
        self._open_browser = autofill.open_browser

    # -- actions --------------------------------------------------------

    def start_analysis(self, limit: int, include_links: bool = True) -> None:
        """Fetch and analyse the junk folder in the background."""
        limit = max(1, min(int(limit), MAX_LIMIT))
        self._start("analysing", self._analyse, limit, include_links)

    def start_sending(self, group_ids: list[str], note: str = "",
                      delete: bool = False) -> None:
        """Send the selected reports in the background."""
        with self._lock:
            if self._plan is None:
                raise ConflictError("Nothing to send: run an analysis.")
            groups = [group for group in self._plan.groups
                      if group.id in set(group_ids) and group.sends_email]
        if not groups:
            raise ValueError("No report selected.")
        self._start("sending", self._send, groups, note[:5000], delete)

    def snapshot(self) -> dict:
        """Return the state displayed by the interface, as JSON data."""
        with self._lock:
            state = {
                "phase": self._phase,
                "progress": dict(self._progress),
                "error": self._error,
                "account": self._authenticator.signed_in_username() or "",
                "planVersion": self._plan_version,
                "results": list(self._results),
                "autofill": {key: dict(value)
                             for key, value in self._autofill.items()},
                "plan": _plan_to_json(self._plan, self._learned)
                if self._plan else None,
            }
        return state

    def mark_reported(self, group_ids: list[str]) -> int:
        """Record groups reported by hand (web form) and hide them.

        Returns the number of groups marked.
        """
        with self._lock:
            if self._phase in ("analysing", "sending"):
                raise ConflictError("An operation is already running.")
            if self._plan is None:
                raise ConflictError("Nothing to mark: run an analysis.")
            wanted = set(group_ids)
            marked = [group for group in self._plan.groups
                      if group.id in wanted]
            if not marked:
                raise ValueError("No report selected.")
            for group in marked:
                for index in group.entries:
                    self._ledger.record(
                        self._plan.samples[index].fingerprint, group.email)
            self._ledger.save()
            self._plan.groups = [group for group in self._plan.groups
                                 if group.id not in wanted]
            self._plan_version += 1
        return len(marked)

    def start_autofill(self, group_id: str) -> None:
        """Open the group's web form in a browser and fill it in."""
        with self._lock:
            try:
                group = _find_group(self._plan, group_id)
            except KeyError:
                raise ValueError("Unknown report.") from None
            form_url = group.policy.form_url if group.policy else ""
            if not form_url.startswith("https://"):
                raise ValueError("This provider has no web form.")
            current = self._autofill.get(group_id, {})
            if current.get("state") == "running":
                raise ConflictError("The form is already being filled in.")
            self._autofill[group_id] = {"state": "running",
                                        "message": "Opening the browser…"}
            data = self._form_data(group)
        threading.Thread(target=self._run_autofill,
                         args=(group_id, form_url, data),
                         daemon=True).start()

    def _set_autofill(self, group_id: str, state: str,
                      message: str) -> None:
        with self._lock:
            self._autofill[group_id] = {"state": state,
                                        "message": sanitize(message)}

    def _run_autofill(self, group_id: str, url: str,
                      data: autofill.FormData) -> None:
        try:
            driver = self._open_browser()
            self._browsers.append(driver)
            autofill.fill_form(
                driver, url, data,
                status=lambda text: self._set_autofill(group_id, "running",
                                                       text))
            self._set_autofill(group_id, "done",
                               "Form filled in: review it and submit it "
                               "in the browser window, then mark these "
                               "spams as reported.")
        except Exception as exc:  # Shown to the user, never swallowed.
            log.exception("Automatic filling failed")
            self._set_autofill(group_id, "error", str(exc))

    def _form_data(self, group: ReportGroup) -> autofill.FormData:
        """Gather what the abuse form may ask for (lock held)."""
        plan = self._plan
        indexes = sorted(group.entries)
        findings = [finding for index in indexes
                    for finding in group.entries[index]]
        domains = list(dict.fromkeys(
            [finding.resource for finding in findings
             if finding.kind in (LINK_DOMAIN, SENDING_DOMAIN)]
            + [finding.via for finding in findings
               if finding.kind == LINK_HOSTING and finding.via]))
        ips = [value for value in group.resources()
               if normalise_public_ip(value)]
        urls = [url for index in indexes
                for url in plan.samples[index].evidence.links
                if any(_host_in(url, domain) for domain in domains)]
        dates = []
        for index in indexes:
            try:
                dates.append(parsedate_to_datetime(
                    plan.samples[index].evidence.date))
            except (TypeError, ValueError, IndexError):
                continue
        part = build_group_report(group, plan.samples)[0]
        directory = autofill.upload_directory() / group.id
        return autofill.FormData(
            reporter_email=self._authenticator.signed_in_username() or "",
            reporter_name=self._authenticator.signed_in_name(),
            subject=part.subject, body=part.body,
            urls=list(dict.fromkeys(urls)), domains=domains, ips=ips,
            first_seen=min(dates, key=lambda moment: moment.timestamp())
            if dates else None,
            attachments=autofill.write_attachments(
                [content for _, content in part.attachments], directory))

    def eml_archive(self, group_id: str) -> bytes:
        """Return a ZIP of the messages of a group (for upload forms)."""
        with self._lock:
            plan = self._plan
        group = _find_group(plan, group_id)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for number, index in enumerate(sorted(group.entries), 1):
                archive.writestr(f"spam-{number:03d}.eml",
                                 plan.samples[index].raw)
        return buffer.getvalue()

    # -- background work ------------------------------------------------

    def _start(self, phase: str, target, *args) -> None:
        with self._lock:
            if self._phase in ("analysing", "sending"):
                raise ConflictError("An operation is already running.")
            self._phase, self._error = phase, ""
            self._progress = {"done": 0, "total": 0, "label": ""}
        thread = threading.Thread(target=self._run, args=(target, *args),
                                  daemon=True)
        thread.start()

    def _run(self, target, *args) -> None:
        try:
            target(*args)
        except Exception as exc:  # Reported to the user, never swallowed.
            log.exception("Background operation failed")
            with self._lock:
                self._phase, self._error = "error", str(exc)

    def _report_progress(self, done: int, total: int, label: str) -> None:
        with self._lock:
            self._progress = {"done": done, "total": total, "label": label}

    def _analyse(self, limit: int, include_links: bool) -> None:
        client = self._client_factory(required_scopes())
        try:
            learned = learn_from_replies(client, self._policies,
                                         REPORT_SUBJECT_PREFIX,
                                         self._report_progress)
        except GraphError as exc:  # Never block the analysis.
            log.warning("Could not analyse the replies: %s", exc)
            learned = []
        samples = fetch_samples(client, limit, self._report_progress)
        planner = self._planner_factory(
            include_links=include_links,
            policies=policy_lookup(self._policies))
        plan = planner.plan(samples, self._report_progress)
        with self._lock:
            self._plan, self._results = plan, []
            self._learned = [{"email": policy.email,
                              "status": policy.status}
                             for policy in learned]
            self._plan_version += 1
            self._phase = "ready"

    def _send(self, groups, note: str, delete: bool) -> None:
        # Incremental consent: Mail.Send (and Mail.ReadWrite) are only
        # requested now, possibly opening the browser once.
        client = self._client_factory(required_scopes(send=True,
                                                      delete=delete))
        results = send_reports(client, self._plan, groups, self._ledger,
                               note=note, delete=delete,
                               progress=self._report_progress)
        with self._lock:
            self._results = [{
                "groupId": result.group_id, "email": result.email,
                "part": result.part, "parts": result.parts,
                "ok": result.ok, "error": sanitize(result.error),
            } for result in results]
            self._phase = "done"

    def _default_client(self, scopes: list[str]) -> GraphMailClient:
        self._authenticator.get_access_token(scopes)
        return GraphMailClient(self._authenticator.token_provider(scopes))


# -- JSON views -------------------------------------------------------------

def _host_in(url: str, domain: str) -> bool:
    """Tell whether *url* points to *domain* or one of its sub-domains."""
    from urllib.parse import urlsplit

    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host == domain or host.endswith("." + domain)


def _find_group(plan: CampaignPlan | None, group_id: str):
    for group in plan.groups if plan else []:
        if group.id == group_id:
            return group
    raise KeyError(group_id)


def _plan_to_json(plan: CampaignPlan, learned: list[dict]) -> dict:
    """Serialise a plan for the interface (all text sanitised)."""
    groups = []
    for group in plan.groups:
        parts = build_group_report(group, plan.samples)
        messages = []
        for index in sorted(group.entries):
            evidence = plan.samples[index].evidence
            messages.append({
                "date": sanitize(evidence.date),
                "subject": sanitize(evidence.subject),
                "sender": sanitize(evidence.sender),
                "findings": [{"kind": finding.kind,
                              "resource": sanitize(finding.resource),
                              "via": sanitize(finding.via)}
                             for finding in group.entries[index]],
            })
        policy = group.policy
        groups.append({
            "id": group.id,
            "email": group.email,
            "name": sanitize(group.display_name),
            "organisation": sanitize(group.organisation),
            "optional": group.optional,
            "sendsEmail": group.sends_email,
            "formUrl": policy.form_url if policy and
            policy.form_url.startswith("https://") else "",
            "formHint": policy.form_hint if policy else "",
            "count": len(group.entries),
            "parts": len(parts),
            "kinds": sorted({finding.kind
                             for findings in group.entries.values()
                             for finding in findings}),
            "resources": [sanitize(value) for value in group.resources()],
            "messages": messages,
            "preview": sanitize(parts[0].body) if parts else "",
        })
    return {
        "count": len(plan.samples),
        "alreadyReported": plan.already_reported,
        "orphans": [sanitize(plan.samples[index].evidence.subject)
                    for index in plan.orphans],
        "learned": learned,
        "groups": groups,
    }


# -- HTTP layer -------------------------------------------------------------

def _read_static(name: str) -> bytes:
    return resources.files("counter_spam").joinpath("web", name) \
        .read_bytes()


class _Handler(BaseHTTPRequestHandler):
    """Routes requests to :class:`CounterSpamApp`."""

    server_version = "CounterSpam"
    sys_version = ""
    # Set on the subclass created by :func:`make_server`.
    app: CounterSpamApp
    token: str
    allowed_hosts: frozenset

    def log_message(self, format, *args):  # Signature imposed by stdlib.
        log.debug("%s - %s", self.address_string(), format % args)

    # -- helpers --------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in {**_SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data) -> None:
        self._send(status, json.dumps(data).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _host_is_allowed(self) -> bool:
        return self.headers.get("Host", "") in self.allowed_hosts

    def _token_is_valid(self, candidate: str | None) -> bool:
        return bool(candidate) and hmac.compare_digest(
            candidate.encode(), self.token.encode())

    def _query(self) -> dict:
        return {key: values[0] for key, values in
                parse_qs(urlsplit(self.path).query).items()}

    # -- verbs ----------------------------------------------------------

    def do_GET(self):  # Name imposed by the stdlib.
        if not self._host_is_allowed():
            return self._error(HTTPStatus.FORBIDDEN, "Invalid host")
        path, query = urlsplit(self.path).path, self._query()
        if path in _STATIC_FILES:
            if path == "/" and not self._token_is_valid(query.get("t")):
                return self._error(HTTPStatus.FORBIDDEN,
                                   "Open the address printed in the "
                                   "terminal.")
            name, content_type = _STATIC_FILES[path]
            return self._send(HTTPStatus.OK, _read_static(name),
                              content_type)
        if path == "/api/state":
            if not self._token_is_valid(self.headers.get(TOKEN_HEADER)):
                return self._error(HTTPStatus.FORBIDDEN, "Invalid token")
            return self._json(HTTPStatus.OK, self.app.snapshot())
        if path == "/api/eml":
            # Plain link navigation: the token travels in the query.
            if not self._token_is_valid(query.get("t")):
                return self._error(HTTPStatus.FORBIDDEN, "Invalid token")
            try:
                archive = self.app.eml_archive(query.get("group", ""))
            except KeyError:
                return self._error(HTTPStatus.NOT_FOUND, "Unknown group")
            return self._send(
                HTTPStatus.OK, archive, "application/zip",
                {"Content-Disposition":
                 'attachment; filename="counter-spam-messages.zip"'})
        return self._error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self):  # Name imposed by the stdlib.
        if not self._host_is_allowed():
            return self._error(HTTPStatus.FORBIDDEN, "Invalid host")
        if not self._token_is_valid(self.headers.get(TOKEN_HEADER)):
            return self._error(HTTPStatus.FORBIDDEN, "Invalid token")
        if not self.headers.get("Content-Type", "").startswith(
                "application/json"):
            return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                               "JSON expected")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY_BYTES:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               "Request too large")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            return self._dispatch(urlsplit(self.path).path, payload)
        except ConflictError as exc:
            return self._error(HTTPStatus.CONFLICT, str(exc))
        except (ValueError, TypeError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _dispatch(self, path: str, payload: dict):
        if path == "/api/analyse":
            self.app.start_analysis(int(payload.get("limit", 50)),
                                    bool(payload.get("links", True)))
        elif path == "/api/send":
            group_ids = payload.get("groups") or []
            if not isinstance(group_ids, list):
                raise ValueError("'groups' must be a list")
            self.app.start_sending([str(item) for item in group_ids],
                                   str(payload.get("note", "")),
                                   bool(payload.get("delete", False)))
        elif path == "/api/mark":
            group_ids = payload.get("groups") or []
            if not isinstance(group_ids, list):
                raise ValueError("'groups' must be a list")
            count = self.app.mark_reported([str(item) for item in group_ids])
            return self._json(HTTPStatus.OK, {"ok": True, "marked": count})
        elif path == "/api/autofill":
            self.app.start_autofill(str(payload.get("group", "")))
        elif path == "/api/quit":
            self._json(HTTPStatus.OK, {"ok": True})
            threading.Thread(target=self.server.shutdown,
                             daemon=True).start()
            return None
        else:
            return self._error(HTTPStatus.NOT_FOUND, "Not found")
        return self._json(HTTPStatus.ACCEPTED, {"ok": True})


def make_server(app: CounterSpamApp, port: int = 0,
                token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    """Create the HTTP server and return it with the URL to open."""
    token = token or secrets.token_urlsafe(32)
    handler = type("Handler", (_Handler,), {"app": app, "token": token})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    actual_port = server.server_address[1]
    handler.allowed_hosts = frozenset(
        {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}"})
    return server, f"http://127.0.0.1:{actual_port}/?t={token}"


def run(app: CounterSpamApp, *, port: int = 0, open_browser: bool = True,
        announce: Callable[[str], None] = print) -> None:
    """Serve the interface until the user quits it or presses Ctrl+C."""
    server, url = make_server(app, port)
    announce(f"Counter-Spam is running at {url}")
    announce("Keep this address private. Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    finally:
        server.server_close()
