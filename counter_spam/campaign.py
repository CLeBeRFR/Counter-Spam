"""Reporting strategy: who to report each spam to, grouped per abuse desk.

For every spam, three kinds of responsible parties are looked up:

``sending-server``
    The network owner (hosting provider) of the IP address that delivered
    the message to Outlook.  This is the most reliable indicator: it is
    observed by Microsoft, not declared by the spammer.
``sending-domain``
    The registrar of a domain *authenticated* by SPF or DKIM.
``link-domain`` / ``link-hosting``
    The registrar of the domains advertised in the body, and the hosting
    provider of their web site.  Taking these down stops the scam itself
    (phishing page, fake shop...).

Findings are then grouped by abuse address, so that each provider gets a
**single report listing all the relevant spams**, with the evidence that
concerns it, instead of one e-mail per spam.  A local ledger records what
was already reported so that nothing is sent twice.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .graph import GraphError, GraphMailClient
from .headers import SpamEvidence, collect_evidence, normalise_public_ip, \
    parse_message
from .providers import APWG_ADDRESS, ProviderPolicy, \
    is_brand_protection_registrar, policy_for
from .rdap import AbuseLookup, RdapClient

log = logging.getLogger(__name__)

SENDING_SERVER = "sending-server"
SENDING_DOMAIN = "sending-domain"
LINK_DOMAIN = "link-domain"
LINK_HOSTING = "link-hosting"
DECLARED = "declared"

#: Human-readable description of each finding kind (used in reports).
FINDING_LABELS = {
    SENDING_SERVER: "sending server",
    SENDING_DOMAIN: "authenticated sending domain",
    LINK_DOMAIN: "domain advertised in the message",
    LINK_HOSTING: "web site advertised in the message",
    DECLARED: "abuse contact declared in the message",
}

#: Kinds whose lookup targets a registrar rather than a network.
_REGISTRAR_KINDS = frozenset({SENDING_DOMAIN, LINK_DOMAIN})

Progress = Callable[[int, int, str], None]


def _no_progress(done: int, total: int, label: str) -> None:
    """Default progress callback: do nothing."""


@dataclass
class Sample:
    """One spam message, as fetched from the Junk folder."""

    graph_id: str
    raw: bytes
    evidence: SpamEvidence

    @property
    def fingerprint(self) -> str:
        """Stable identifier of the message content."""
        return hashlib.sha256(self.raw).hexdigest()

    @classmethod
    def from_raw(cls, graph_id: str, raw: bytes) -> "Sample":
        return cls(graph_id, raw, collect_evidence(parse_message(raw)))


@dataclass(frozen=True)
class Finding:
    """Why a sample concerns an abuse desk."""

    kind: str
    #: The IP address or domain under the desk's responsibility.
    resource: str
    #: For ``link-hosting``: the advertised domain served from *resource*.
    via: str = ""

    def describe(self) -> str:
        label = FINDING_LABELS.get(self.kind, self.kind)
        suffix = f" (serving {self.via})" if self.via else ""
        return f"{label} {self.resource}{suffix}"


@dataclass
class ReportGroup:
    """All the samples to report to one abuse address."""

    email: str
    organisation: str = ""
    policy: ProviderPolicy | None = None
    #: Sample index -> findings concerning this desk.
    entries: dict[int, list[Finding]] = field(default_factory=dict)
    #: Optional groups (aggregators) are not selected by default.
    optional: bool = False

    @property
    def id(self) -> str:
        """Short identifier, safe to use in URLs and HTML."""
        return hashlib.sha256(self.email.encode()).hexdigest()[:12]

    @property
    def display_name(self) -> str:
        if self.policy:
            return self.policy.name
        return self.organisation or self.email

    @property
    def sends_email(self) -> bool:
        return self.policy is None or self.policy.accepts_email

    def add(self, index: int, finding: Finding) -> None:
        findings = self.entries.setdefault(index, [])
        if finding not in findings:
            findings.append(finding)

    def resources(self) -> list[str]:
        """Every resource of this desk mentioned in the group."""
        return list(dict.fromkeys(
            finding.resource for findings in self.entries.values()
            for finding in findings))


# -- DNS --------------------------------------------------------------------

def resolve_addresses(domain: str, limit: int = 2) -> list[str]:
    """Return up to *limit* public IP addresses of *domain*.

    Only the *registered* domain is resolved, never the full host found in
    the link: spammers use per-recipient sub-domains, and resolving them
    would confirm to their DNS server that the address is alive.  The web
    page itself is never fetched.
    """
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    addresses = (normalise_public_ip(info[4][0]) for info in infos)
    return [ip for ip in dict.fromkeys(addresses) if ip][:limit]


# -- ledger -----------------------------------------------------------------

class ReportLedger:
    """Remember which message was reported to which address.

    Only content hashes and abuse addresses are stored, nothing about the
    messages themselves.
    """

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._entries: dict[str, list[str]] = {}
        if path is not None:
            self._load()

    def _load(self) -> None:
        try:
            with self._path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            log.warning("Ignoring unreadable ledger %s: %s", self._path, exc)
            return
        if isinstance(data, dict):
            self._entries = {key: list(value) for key, value in data.items()
                             if isinstance(value, list)}

    def already_reported(self, fingerprint: str, email: str) -> bool:
        return email in self._entries.get(fingerprint, [])

    def record(self, fingerprint: str, email: str) -> None:
        emails = self._entries.setdefault(fingerprint, [])
        if email not in emails:
            emails.append(email)

    def save(self) -> None:
        """Write the ledger atomically (no half-written file on crash)."""
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(self._entries, handle)
        os.replace(temporary, self._path)


# -- planning ---------------------------------------------------------------

@dataclass
class CampaignPlan:
    """Outcome of the planning step."""

    samples: list[Sample]
    groups: list[ReportGroup]
    #: Number of (sample, address) pairs skipped as already reported.
    already_reported: int = 0
    #: Indexes of the samples for which no abuse contact was found.
    orphans: list[int] = field(default_factory=list)


class CampaignPlanner:
    """Turn spam samples into report groups.

    Args:
        rdap: RDAP client used for every lookup.
        resolve: DNS resolver (default: :func:`resolve_addresses`).
        ledger: reports already sent, to avoid duplicates.
        include_links: also report the domains advertised in the body.
        include_apwg: add an optional group for the APWG.
        policies: ``(email, organisation) -> ProviderPolicy`` lookup
            (default: :func:`providers.policy_for`).
        workers: number of concurrent network lookups.
    """

    def __init__(self, rdap: RdapClient, *,
                 resolve: Callable[[str], list[str]] | None = None,
                 ledger: ReportLedger | None = None,
                 include_links: bool = True,
                 include_apwg: bool = True,
                 policies: Callable[[str, str], ProviderPolicy | None]
                 | None = None,
                 workers: int = 8) -> None:
        self._rdap = rdap
        self._resolve = resolve or resolve_addresses
        self._ledger = ledger or ReportLedger(None)
        self._include_links = include_links
        self._include_apwg = include_apwg
        self._policies = policies or (lambda email, organisation:
                                      policy_for(email))
        self._workers = workers
        self._lookups: dict[str, AbuseLookup] = {}

    def plan(self, samples: Sequence[Sample],
             progress: Progress = _no_progress) -> CampaignPlan:
        """Look up every indicator and group the findings per address."""
        samples = list(samples)
        candidates = [self._candidates(sample) for sample in samples]

        # Round 1: sending servers, sending domains, advertised domains.
        self._lookup_all({value for items in candidates
                          for _, value in items}, progress)

        # Round 2: hosting providers of the advertised domains.
        hosting = self._hosting_candidates(candidates, progress)
        self._lookup_all({ip for items in hosting for ip, _ in items},
                         progress)
        for items, extra in zip(candidates, hosting):
            items.extend((LINK_HOSTING, (ip, domain)) for ip, domain in extra)

        return self._group(samples, candidates)

    # -- internals ----------------------------------------------------------

    def _candidates(self, sample: Sample) -> list[tuple[str, object]]:
        """Return the ``(kind, target)`` pairs to look up for a sample."""
        evidence = sample.evidence
        items: list[tuple[str, object]] = []
        items += [(SENDING_SERVER, ip) for ip in evidence.sender_ips]
        items += [(SENDING_DOMAIN, domain)
                  for domain in evidence.verified_domains]
        if self._include_links:
            items += [(LINK_DOMAIN, host) for host in evidence.link_hosts]
        return items

    def _hosting_candidates(self, candidates, progress: Progress):
        """Resolve the registered advertised domains to their web hosts."""
        domains = sorted({self._lookups[target].resource
                          for items in candidates for kind, target in items
                          if kind == LINK_DOMAIN and target in self._lookups
                          and self._lookups[target].resource})
        addresses: dict[str, list[str]] = {}
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            for done, (domain, ips) in enumerate(
                    zip(domains, pool.map(self._resolve, domains)), 1):
                addresses[domain] = ips
                progress(done, len(domains), "DNS")
        result = []
        for items in candidates:
            pairs = []
            for kind, target in items:
                lookup = self._lookups.get(target) \
                    if kind == LINK_DOMAIN else None
                if lookup and lookup.resource:
                    pairs += [(ip, lookup.resource)
                              for ip in addresses.get(lookup.resource, [])]
            result.append(list(dict.fromkeys(pairs)))
        return result

    def _lookup_all(self, targets: Iterable[str],
                    progress: Progress) -> None:
        """Run the RDAP lookups not cached yet, concurrently."""
        pending = sorted(set(targets) - set(self._lookups))
        if not pending:
            return
        progress(0, len(pending), "RDAP")
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            for done, (target, lookup) in enumerate(
                    zip(pending, pool.map(self._rdap.lookup, pending)), 1):
                self._lookups[target] = lookup
                progress(done, len(pending), "RDAP")

    def _group(self, samples: list[Sample], candidates) -> CampaignPlan:
        groups: dict[str, ReportGroup] = {}
        plan = CampaignPlan(samples=samples, groups=[])

        def add(index: int, email: str, organisation: str,
                finding: Finding) -> None:
            if self._ledger.already_reported(samples[index].fingerprint,
                                             email):
                plan.already_reported += 1
                return
            group = groups.get(email)
            if group is None:
                group = groups[email] = ReportGroup(
                    email=email, organisation=organisation,
                    policy=self._policies(email, organisation))
            group.add(index, finding)

        for index, items in enumerate(candidates):
            found = False
            for kind, target in items:
                via = ""
                if kind == LINK_HOSTING:
                    target, via = target
                lookup = self._lookups.get(target)
                if not lookup or not lookup.emails:
                    continue
                if kind in _REGISTRAR_KINDS and \
                        is_brand_protection_registrar(lookup.organisation):
                    continue
                finding = Finding(kind, lookup.resource or target, via)
                for email in lookup.emails:
                    add(index, email, lookup.organisation, finding)
                found = True
            # Self-declared contacts are a last resort: they come from the
            # spammer and could point anywhere.
            if not found:
                for email in samples[index].evidence.declared_abuse_contacts:
                    add(index, email, "",
                        Finding(DECLARED, email))
                    found = True
            if not found:
                plan.orphans.append(index)

        # The APWG analyses the advertised sites: it is only offered when
        # links are reported at all.
        if self._include_apwg and self._include_links:
            apwg = ReportGroup(email=APWG_ADDRESS,
                               organisation="Anti-Phishing Working Group",
                               optional=True)
            for index, sample in enumerate(samples):
                if sample.evidence.links and not self._ledger \
                        .already_reported(sample.fingerprint, APWG_ADDRESS):
                    apwg.add(index, Finding(LINK_DOMAIN, ", ".join(
                        sample.evidence.link_hosts[:3])))
            if apwg.entries:
                groups[APWG_ADDRESS] = apwg

        plan.groups = sorted(groups.values(),
                             key=lambda group: (group.optional,
                                                -len(group.entries),
                                                group.email))
        return plan


# -- fetching and sending ---------------------------------------------------

def fetch_samples(client: GraphMailClient, limit: int,
                  progress: Progress = _no_progress) -> list[Sample]:
    """Download the *limit* most recent junk messages."""
    summaries = client.list_junk_messages(limit=limit)
    samples = []
    for done, summary in enumerate(summaries, 1):
        progress(done, len(summaries), "Outlook")
        samples.append(Sample.from_raw(
            summary.id, client.get_message_mime(summary.id)))
    return samples


@dataclass
class SendResult:
    """Outcome of sending one report part."""

    group_id: str
    email: str
    part: int
    parts: int
    ok: bool
    error: str = ""


def send_reports(client: GraphMailClient, plan: CampaignPlan,
                 groups: Sequence[ReportGroup], ledger: ReportLedger, *,
                 note: str = "", delete: bool = False,
                 progress: Progress = _no_progress,
                 pause: float = 2.0) -> list[SendResult]:
    """Send the reports of *groups* and record them in the ledger.

    Reports are sent sequentially with a short *pause* to stay well below
    Outlook's sending limits.  When *delete* is true, messages included in
    at least one successful report are moved to *Deleted Items*.
    """
    # Imported here to keep the planning code free of formatting concerns.
    from .report import build_group_report

    results: list[SendResult] = []
    reported: set[int] = set()
    parts = [(group, part) for group in groups if group.sends_email
             for part in build_group_report(group, plan.samples, note=note)]
    for done, (group, part) in enumerate(parts, 1):
        progress(done - 1, len(parts), group.email)
        try:
            client.send_mail(list(part.recipients), part.subject, part.body,
                             attachments=part.attachments)
        except (GraphError, ValueError) as exc:
            log.error("Report to %s not sent: %s", group.email, exc)
            results.append(SendResult(group.id, group.email, part.number,
                                      part.total, False, str(exc)))
            continue
        for index in part.sample_indexes:
            ledger.record(plan.samples[index].fingerprint, group.email)
            reported.add(index)
        ledger.save()
        results.append(SendResult(group.id, group.email, part.number,
                                  part.total, True))
        if done < len(parts):
            time.sleep(pause)
    progress(len(parts), len(parts), "")

    if delete:
        for index in sorted(reported):
            try:
                client.move_to_deleted_items(plan.samples[index].graph_id)
            except GraphError as exc:
                log.error("Could not move message: %s", exc)
    return results
