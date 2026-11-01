"""Learning from the abuse desks' replies.

Many providers never read their abuse mailbox and answer every report
with an automatic reply pointing to a web form; some addresses published
in RDAP simply bounce.  Sending them e-mails is pointless, so the replies
to our reports are analysed and the outcome is remembered locally:

``form``
    the desk asks for its web form: no more e-mails, the interface offers
    the form instead;
``bounced``
    the address does not exist: no more e-mails.

Replies are written by third parties and are therefore **untrusted**:

* a form link is only kept if it is HTTPS and belongs to the abuse
  desk's own organisation (same main domain label, e.g. ``worldstream.nl``
  and ``worldstream.com``) or to a recognised abuse-handling platform;
* nothing in a reply is ever executed, fetched or followed automatically.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .graph import GraphMailClient, ReceivedMessage
from .headers import normalise_domain
from .providers import ProviderPolicy

log = logging.getLogger(__name__)

FORM = "form"
BOUNCED = "bounced"

#: Third-party platforms that abuse desks use to receive reports.
TRUSTED_ABUSE_PLATFORMS = ("cleandns.space", "cleandns.com")

#: Phrases meaning "e-mail reports are not processed".
_REFUSAL_PATTERNS = re.compile(
    r"not (?:actively )?monitored|no longer monitored|"
    r"(?:do|does|will) not (?:accept|process|review|read)|"
    r"(?:will|shall) not be (?:processed|reviewed|read|answered|actioned)|"
    r"no action will be taken|must be submitted (?:through|via|using)|"
    r"only accept(?:s|ed)? .{0,40}(?:form|portal)",
    re.IGNORECASE)
#: Phrases pointing to a web form.
_FORM_PATTERNS = re.compile(
    r"web ?form|web-form|online (?:reporting )?form|reporting form|"
    r"abuse (?:reporting )?form|report(?:ing)? (?:page|portal)|"
    r"fill (?:out|in) the form|use (?:our|the) form",
    re.IGNORECASE)
#: Delivery failure notifications.
_BOUNCE_SUBJECT = re.compile(
    r"^(?:undeliverable|undelivered|delivery (?:status notification )?"
    r"\(?fail|mail delivery failed|returned mail|non remis|"
    r"échec de la remise)", re.IGNORECASE)
_BOUNCE_SENDER = re.compile(r"^(?:postmaster|mailer-daemon)@", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)


@dataclass(frozen=True)
class LearnedPolicy:
    """What a reply taught us about an abuse address."""

    email: str
    status: str
    form_url: str = ""
    learned_on: str = ""
    reply_from: str = ""

    def to_provider_policy(self, name: str) -> ProviderPolicy:
        if self.status == BOUNCED:
            hint = (f"This address bounced on {self.learned_on}: it does "
                    "not accept e-mails.")
        else:
            hint = (f"Learned from their automatic reply of "
                    f"{self.learned_on}: e-mails are not processed.")
        return ProviderPolicy(name=name, form_url=self.form_url,
                              form_hint=hint, accepts_email=False)


# -- classification ---------------------------------------------------------

def _main_label(domain: str) -> str:
    """Return the organisation label of a domain (``worldstream``).

    ``abuse.example.co.uk`` -> ``example``: two-letter second-level
    labels under a country code (``co``, ``ac``...) are skipped.
    """
    labels = domain.lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else domain


def _is_trusted_host(host: str, organisation_domains: list[str]) -> bool:
    host = normalise_domain(host) or ""
    if not host:
        return False
    if any(host == platform or host.endswith("." + platform)
           for platform in TRUSTED_ABUSE_PLATFORMS):
        return True
    labels = {_main_label(domain) for domain in organisation_domains}
    return _main_label(host) in labels


def find_form_url(text: str, abuse_email: str, sender: str) -> str:
    """Return the most relevant trusted HTTPS form link of a reply."""
    domains = [address.rsplit("@", 1)[-1]
               for address in (abuse_email, sender) if "@" in address]
    candidates = []
    for url in _URL_RE.findall(text):
        url = url.rstrip(".,;:!?")
        parts = urlsplit(url)
        if parts.scheme.lower() != "https" or \
                not _is_trusted_host(parts.hostname or "", domains):
            continue
        candidates.append(url)
    # Prefer links that are explicitly about abuse reporting.
    for url in candidates:
        if re.search(r"abuse|report", url, re.IGNORECASE):
            return url
    return candidates[0] if candidates else ""


def classify_reply(abuse_email: str, reply: ReceivedMessage, text: str,
                   today: str | None = None) -> LearnedPolicy | None:
    """Return what *reply* teaches about *abuse_email*, if anything."""
    learned_on = today or date.today().isoformat()
    if _BOUNCE_SUBJECT.search(reply.subject) or \
            _BOUNCE_SENDER.search(reply.sender):
        if abuse_email.lower() in text.lower():
            return LearnedPolicy(abuse_email, BOUNCED, "", learned_on,
                                 reply.sender)
        return None
    form_url = find_form_url(text, abuse_email, reply.sender)
    refuses = bool(_REFUSAL_PATTERNS.search(text))
    mentions_form = bool(_FORM_PATTERNS.search(text))
    if refuses or (mentions_form and form_url):
        return LearnedPolicy(abuse_email, FORM, form_url, learned_on,
                             reply.sender)
    return None


# -- storage ----------------------------------------------------------------

class PolicyStore:
    """Learned policies, persisted as JSON in the cache directory."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._policies: dict[str, LearnedPolicy] = {}
        self._processed: set[str] = set()
        if path is not None:
            self._load()

    def _load(self) -> None:
        try:
            with self._path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            log.warning("Ignoring unreadable %s: %s", self._path, exc)
            return
        for item in data.get("policies", []):
            try:
                policy = LearnedPolicy(**item)
            except TypeError:
                continue
            self._policies[policy.email] = policy
        self._processed = set(data.get("processed_replies", []))

    def get(self, email: str) -> LearnedPolicy | None:
        return self._policies.get(email.lower())

    def all(self) -> list[LearnedPolicy]:
        return sorted(self._policies.values(), key=lambda p: p.email)

    def learn(self, policy: LearnedPolicy) -> bool:
        """Store *policy*; return whether it is new information."""
        policy = LearnedPolicy(policy.email.lower(), policy.status,
                               policy.form_url, policy.learned_on,
                               policy.reply_from)
        previous = self._policies.get(policy.email)
        # Keep a known form link if a later reply carries none.
        if previous and previous.form_url and not policy.form_url:
            policy = LearnedPolicy(policy.email, policy.status,
                                   previous.form_url, policy.learned_on,
                                   policy.reply_from)
        self._policies[policy.email] = policy
        return previous is None or previous.status != policy.status

    def forget(self, email: str) -> None:
        self._policies.pop(email.lower(), None)

    def was_processed(self, reply_id: str) -> bool:
        return reply_id in self._processed

    def mark_processed(self, reply_id: str) -> None:
        self._processed.add(reply_id)

    def save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump({"policies": [asdict(p) for p in self.all()],
                       "processed_replies": sorted(self._processed)},
                      handle, indent=1)
        os.replace(temporary, self._path)


def learn_from_replies(client: GraphMailClient, store: PolicyStore,
                       subject_prefix: str,
                       progress: Callable[[int, int, str], None]
                       = lambda done, total, label: None
                       ) -> list[LearnedPolicy]:
    """Analyse new replies to our reports; return what was learned."""
    conversations = client.list_sent_conversations(subject_prefix)
    replies = [reply for reply in client.list_replies(set(conversations))
               if not store.was_processed(reply.id)]
    learned = []
    for done, reply in enumerate(replies, 1):
        progress(done, len(replies), "Replies")
        text = client.get_message_text(reply.id)
        for email in conversations.get(reply.conversation_id, []):
            policy = classify_reply(email, reply, text)
            if policy and store.learn(policy):
                learned.append(policy)
                log.info("%s: %s (%s)", email, policy.status,
                         policy.form_url or "no form link")
        store.mark_processed(reply.id)
    store.save()
    return learned


def policy_lookup(store: PolicyStore
                  ) -> Callable[[str, str], ProviderPolicy | None]:
    """Return a lookup giving priority to what replies taught us."""
    from .providers import policy_for

    def lookup(email: str, organisation: str) -> ProviderPolicy | None:
        known = policy_for(email)
        learned = store.get(email)
        if learned is None:
            return known
        name = known.name if known else (organisation or email)
        policy = learned.to_provider_policy(name)
        if known and known.form_url and not policy.form_url:
            policy = ProviderPolicy(policy.name, known.form_url,
                                    policy.form_hint, False)
        return policy

    return lookup
