"""Command-line interface of Counter-Spam.

Read-only commands (``list``, ``show``, ``analyze``) only ever request the
``Mail.Read`` permission.  ``report`` and ``gui`` additionally request
``Mail.Send`` when a report is actually sent, and ``Mail.ReadWrite`` only
when the user asks for the reported messages to be moved away.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Sequence

import requests

from . import __version__
from .auth import (AUTH_METHODS, AuthenticationError, OutlookAuthenticator,
                   required_scopes)
from .campaign import CampaignPlan, CampaignPlanner, FINDING_LABELS, \
    ReportLedger, fetch_samples, send_reports
from .config import (DEFAULT_TENANT, ConfigError, cache_dir, load_settings,
                     save_settings)
from .display import message_text, sanitize
from .feedback import (BOUNCED, PolicyStore, learn_from_replies,
                       policy_lookup)
from .graph import GraphError, GraphMailClient, MessageSummary
from .headers import collect_evidence, defang, normalise_public_ip, \
    parse_message
from .rdap import RdapClient
from .report import REPORT_SUBJECT_PREFIX, build_group_report

log = logging.getLogger("counter_spam")

EXIT_OK, EXIT_ERROR, EXIT_INTERRUPTED = 0, 1, 130


# -- helpers ----------------------------------------------------------------

def _out(text: str = "") -> None:
    """Print *text* after removing terminal control sequences."""
    print(sanitize(text), flush=True)


def _authenticator(args: argparse.Namespace) -> OutlookAuthenticator:
    settings = load_settings(args.client_id, args.tenant)
    return OutlookAuthenticator(settings, method=args.auth_method,
                                notify=_notify_sign_in)


def _client(authenticator: OutlookAuthenticator, *, send: bool = False,
            delete: bool = False) -> GraphMailClient:
    """Return a Graph client authorised for exactly the needed scopes."""
    scopes = required_scopes(send=send, delete=delete)
    # Authenticate up-front so that the sign-in prompt appears first.
    authenticator.get_access_token(scopes)
    return GraphMailClient(authenticator.token_provider(scopes))


def _notify_sign_in(message: str) -> None:
    """Show the sign-in instructions, flushed for non-tty output."""
    print(f"\n>>> {message}\n", file=sys.stderr, flush=True)


def _ledger() -> ReportLedger:
    return ReportLedger(cache_dir() / "reported.json")


def _policies() -> PolicyStore:
    return PolicyStore(cache_dir() / "providers.json")


def _learn(client: GraphMailClient, store: PolicyStore) -> None:
    """Analyse the replies to previous reports and tell what changed."""
    try:
        learned = learn_from_replies(client, store, REPORT_SUBJECT_PREFIX)
    except GraphError as exc:  # Never block the analysis.
        log.warning("Could not analyse the replies: %s", exc)
        return
    for policy in learned:
        reason = "address bounced" if policy.status == BOUNCED \
            else "asks for its web form"
        _out(f"Learned from a reply: {policy.email} {reason}"
             + (f" ({policy.form_url})" if policy.form_url else "")
             + "; no more e-mails will be sent to it.")


def _progress(done: int, total: int, label: str) -> None:
    """Single-line progress indicator on stderr."""
    if total:
        end = "\n" if done >= total else ""
        print(f"\r{label} {done}/{total}", end=end, file=sys.stderr,
              flush=True)


def _resolve_message_id(client: GraphMailClient, reference: str) -> str:
    """Accept either a Graph message ID or a 1-based index from ``list``."""
    if reference.isdigit():
        index = int(reference)
        messages = client.list_junk_messages(limit=index)
        if index < 1 or index > len(messages):
            raise ValueError(f"No junk message #{index}.")
        return messages[index - 1].id
    return reference


def _print_summaries(messages: Sequence[MessageSummary]) -> None:
    for index, message in enumerate(messages, start=1):
        _out(f"{index:>3}. {message.received}  {message.sender}")
        _out(f"     {message.subject}")
        _out(f"     id: {message.id}")


def _save_eml(directory: Path, raw: bytes) -> Path:
    """Write *raw* to *directory* with a safe name and private permissions.

    The file name is derived from the content hash, never from the
    (attacker-controlled) subject, which rules out path traversal.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"spam-{hashlib.sha256(raw).hexdigest()[:16]}.eml"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        handle.write(raw)
    return path


def _display_resource(value: str) -> str:
    """Defang domains (clickable in terminals), keep IP addresses as is."""
    return value if normalise_public_ip(value) else defang(value)


def _confirm(question: str) -> bool:
    try:
        return input(f"{question} [y/N] ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def _build_plan(args: argparse.Namespace, client: GraphMailClient,
                ledger: ReportLedger) -> CampaignPlan:
    store = _policies()
    _learn(client, store)
    samples = fetch_samples(client, args.limit, _progress)
    if args.save_eml:
        for sample in samples:
            _save_eml(args.save_eml, sample.raw)
        _out(f"{len(samples)} message(s) saved to {args.save_eml}")
    planner = CampaignPlanner(RdapClient(), ledger=ledger,
                              include_links=not args.no_links,
                              include_apwg=getattr(args, "apwg", True),
                              policies=policy_lookup(store))
    return planner.plan(samples, _progress)


def _print_plan(plan: CampaignPlan) -> None:
    _out(f"{len(plan.samples)} spam(s) analysed, "
         f"{len(plan.groups)} abuse desk(s) concerned.")
    if plan.already_reported:
        _out(f"{plan.already_reported} report(s) already sent before were "
             "skipped.")
    for group in plan.groups:
        parts = build_group_report(group, plan.samples)
        kinds = sorted({FINDING_LABELS[finding.kind]
                        for findings in group.entries.values()
                        for finding in findings})
        flags = " (optional)" if group.optional else ""
        _out("")
        _out(f"* {group.display_name} <{group.email}>{flags}")
        _out(f"  {len(group.entries)} spam(s), {len(parts)} e-mail(s) -- "
             + ", ".join(kinds))
        resources = group.resources()
        _out("  " + ", ".join(map(_display_resource, resources[:6]))
             + (f" (+{len(resources) - 6})" if len(resources) > 6 else ""))
        if not group.sends_email:
            form = group.policy.form_url
            _out("  No e-mail: " + (f"use the web form {form}" if form
                                    else "the address does not accept "
                                         "e-mails"))
        elif group.policy and group.policy.form_url:
            _out(f"  Preferred form: {group.policy.form_url}")
    for index in plan.orphans:
        _out(f"\nNo abuse contact found for: "
             f"{plan.samples[index].evidence.subject}")


# -- commands ---------------------------------------------------------------

def cmd_configure(args: argparse.Namespace) -> int:
    path = save_settings(args.set_client_id, args.set_tenant)
    _out(f"Configuration saved to {path}")
    return EXIT_OK


def cmd_login(args: argparse.Namespace) -> int:
    authenticator = _authenticator(args)
    client = _client(authenticator, send=args.send, delete=args.delete)
    # The username comes from the ID token: reading the Graph profile
    # would require the extra User.Read permission.
    _out(f"Signed in as {authenticator.signed_in_username()}.")
    # Cheap call proving that the mailbox permission really works.
    client.list_junk_messages(limit=1)
    _out("Access to the Junk folder verified.")
    if not authenticator.cache_is_persistent:
        _out("Warning: no encrypted token storage, the sign-in will not "
             "be remembered.")
    return EXIT_OK


def cmd_logout(args: argparse.Namespace) -> int:
    removed = OutlookAuthenticator(
        load_settings(args.client_id, args.tenant)).logout()
    _out(f"Removed {removed} cached account(s).")
    return EXIT_OK


def cmd_whoami(args: argparse.Namespace) -> int:
    authenticator = OutlookAuthenticator(
        load_settings(args.client_id, args.tenant))
    username = authenticator.signed_in_username()
    _out(f"Signed in as {username}." if username else "Not signed in.")
    if not authenticator.cache_is_persistent:
        _out("Warning: no encrypted token storage available.")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    client = _client(_authenticator(args))
    messages = client.list_junk_messages(limit=args.limit)
    if not messages:
        _out("The Junk folder is empty.")
    _print_summaries(messages)
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    client = _client(_authenticator(args))
    message_id = _resolve_message_id(client, args.message)
    message = parse_message(client.get_message_mime(message_id))
    evidence = collect_evidence(message)
    _out(f"From:     {evidence.sender}")
    _out(f"Subject:  {evidence.subject}")
    _out(f"Date:     {evidence.date}")
    _out(f"IPs:      {', '.join(evidence.sender_ips) or '-'}")
    _out(f"Verified: {', '.join(evidence.verified_domains) or '-'}")
    _out(f"Claimed:  {', '.join(evidence.unverified_domains) or '-'}")
    _out(f"Links:    {', '.join(map(defang, evidence.links)) or '-'}")
    _out("-" * 79)
    _out(message_text(message))
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    """Dry run: show which reports would be sent, send nothing."""
    client = _client(_authenticator(args))
    _print_plan(_build_plan(args, client, _ledger()))
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    """Plan the reports, ask once for confirmation, then send them all."""
    authenticator = _authenticator(args)
    ledger = _ledger()
    plan = _build_plan(args, _client(authenticator), ledger)
    _print_plan(plan)
    groups = [group for group in plan.groups
              if group.sends_email and (args.apwg or not group.optional)]
    if not groups:
        _out("\nNothing to send.")
        return EXIT_OK
    count = sum(len(build_group_report(group, plan.samples))
                for group in groups)
    action = " and move the reported spams to Deleted Items" \
        if args.delete else ""
    if not args.yes and not _confirm(
            f"\nSend {count} report e-mail(s) to {len(groups)} abuse "
            f"desk(s){action}?"):
        _out("Nothing sent.")
        return EXIT_OK
    client = _client(authenticator, send=True, delete=args.delete)
    results = send_reports(client, plan, groups, ledger, note=args.note,
                           delete=args.delete, progress=_progress)
    sent = sum(result.ok for result in results)
    _out(f"{sent}/{len(results)} report e-mail(s) sent (copies are in "
         "Sent Items).")
    return EXIT_OK if sent == len(results) else EXIT_ERROR


def cmd_gui(args: argparse.Namespace) -> int:
    """Open the local web interface."""
    from .webui import CounterSpamApp, run

    authenticator = _authenticator(args)
    _client(authenticator)  # Sign in (read-only) before opening the UI.
    run(CounterSpamApp(authenticator, _ledger()), port=args.port,
        open_browser=not args.no_browser, announce=_out)
    return EXIT_OK


# -- argument parsing -------------------------------------------------------

def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _port(value: str) -> int:
    number = int(value)
    if not 0 <= number <= 65535:
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="counter-spam",
        description="Report the spam of your Outlook Junk folder to the "
                    "abuse desks of the providers involved.")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--client-id", help="Entra application ID "
                        "(overrides the built-in one).")
    parser.add_argument("--tenant", help="Entra tenant: common, consumers, "
                        "organizations, a GUID or a domain.")
    parser.add_argument("--auth-method", choices=AUTH_METHODS,
                        default="auto",
                        help="Sign-in flow when needed: browser, device "
                             "code, or auto (default).")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v, -vv).")
    commands = parser.add_subparsers(dest="command", required=True)

    configure = commands.add_parser(
        "configure", help="Use your own application registration.")
    configure.add_argument("--client-id", dest="set_client_id",
                           required=True)
    configure.add_argument("--tenant", dest="set_tenant",
                           default=DEFAULT_TENANT)
    configure.set_defaults(handler=cmd_configure)

    login = commands.add_parser("login", help="Sign in to Outlook.")
    login.add_argument("--send", action="store_true",
                       help="Also consent to sending reports (Mail.Send).")
    login.add_argument("--delete", action="store_true",
                       help="Also consent to moving messages "
                            "(Mail.ReadWrite).")
    login.set_defaults(handler=cmd_login)

    commands.add_parser("logout", help="Forget the cached tokens."
                        ).set_defaults(handler=cmd_logout)
    commands.add_parser("whoami", help="Show the signed-in account."
                        ).set_defaults(handler=cmd_whoami)

    list_cmd = commands.add_parser("list", help="List junk messages.")
    list_cmd.add_argument("-n", "--limit", type=_positive_int, default=25)
    list_cmd.set_defaults(handler=cmd_list)

    show = commands.add_parser("show", help="Display one junk message.")
    show.add_argument("message", help="Index from 'list' or message ID.")
    show.set_defaults(handler=cmd_show)

    gui = commands.add_parser("gui", help="Open the graphical interface "
                              "in the browser.")
    gui.add_argument("--port", type=_port, default=0,
                     help="Local port (default: random).")
    gui.add_argument("--no-browser", action="store_true",
                     help="Only print the address to open.")
    gui.set_defaults(handler=cmd_gui)

    for name, handler, text in (
            ("analyze", cmd_analyze, "Show the grouped reports (dry run)."),
            ("report", cmd_report, "Send the grouped abuse reports.")):
        sub = commands.add_parser(name, help=text)
        sub.add_argument("-n", "--limit", type=_positive_int, default=50)
        sub.add_argument("--no-links", action="store_true",
                         help="Do not report the domains advertised in "
                              "the messages.")
        sub.add_argument("--save-eml", type=Path, metavar="DIR",
                         help="Also save each message as an .eml file.")
        if name == "report":
            sub.add_argument("-y", "--yes", action="store_true",
                             help="Do not ask for confirmation.")
            sub.add_argument("--delete", action="store_true",
                             help="Move reported messages to Deleted "
                                  "Items.")
            sub.add_argument("--apwg", action="store_true",
                             help="Also forward the spams to the "
                                  "Anti-Phishing Working Group.")
            sub.add_argument("--note", default="",
                             help="Personal message added to the reports.")
        sub.set_defaults(handler=handler)
    return parser


def _configure_output(verbosity: int) -> None:
    """Set up logging and make console output robust on Windows."""
    for stream in (sys.stdout, sys.stderr):
        # Legacy Windows consoles (cp1252...) cannot encode every
        # character found in spam: replace instead of crashing.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    logging.basicConfig(format="%(levelname)s: %(message)s",
                        level=logging.WARNING)
    # Only our own logger gets verbose: third-party debug logs may
    # contain request details we do not want on screen.
    log.setLevel(logging.WARNING - 10 * min(verbosity, 2))


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; return the process exit code."""
    args = build_parser().parse_args(argv)
    _configure_output(args.verbose)
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (ConfigError, AuthenticationError, GraphError, ValueError,
            requests.RequestException) as exc:
        log.error("%s", exc)
        return EXIT_ERROR
