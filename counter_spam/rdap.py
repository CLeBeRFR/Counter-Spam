"""Abuse contact discovery through RDAP (RFC 7480-7484, RFC 9083).

RDAP is the IETF successor of WHOIS: structured JSON over HTTPS, with an
explicit ``abuse`` role.  Compared with the former ``whois`` module it

* is pure Python and works identically on Windows, macOS and Linux (the
  ``whois`` package shells out to a system binary and, on Windows, may
  download and run ``whois.exe``);
* supports IP addresses as well as domain names;
* returns only *abuse* contacts.  Registrant or technical addresses of a
  spam domain often belong to the spammer: mailing them would merely
  confirm that the reporting address is alive.

The authoritative server for a domain or an IP block is located with the
IANA bootstrap registries.  No credential is ever sent to RDAP servers.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Iterator

import requests

from .headers import normalise_domain

log = logging.getLogger(__name__)

IANA_BOOTSTRAP_URLS = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
_RDAP_HEADERS = {"Accept": "application/rdap+json, application/json"}


@dataclass(frozen=True)
class AbuseLookup:
    """Result of an RDAP lookup.

    Attributes:
        target: the domain or IP address that was looked up.
        resource: the registered object found (``example.com`` for
            ``mail.example.com``, or the IP address); ``""`` if none.
        organisation: name of the registrar (domains) or of the network
            holder (IP addresses), for display.
        emails: abuse e-mail addresses, most specific first.
    """

    target: str
    resource: str = ""
    organisation: str = ""
    emails: tuple[str, ...] = field(default_factory=tuple)


class RdapClient:
    """Look up abuse e-mail addresses for domains and IP addresses.

    Args:
        timeout: per-request timeout, in seconds.
        session: optional :class:`requests.Session` (useful for tests).
    """

    def __init__(self, *, timeout: float = 15.0,
                 session: requests.Session | None = None) -> None:
        self._timeout = timeout
        self._session = session or requests.Session()
        self._bootstrap: dict[str, list] = {}

    def abuse_contacts(self, target: str) -> list[str]:
        """Return abuse addresses for a domain name or an IP address."""
        return list(self.lookup(target).emails)

    def lookup(self, target: str) -> AbuseLookup:
        """Look up a domain name or an IP address.

        Lookup failures are logged and yield an empty result: a missing
        contact must not abort the processing of the other messages.
        """
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return self._lookup_domain(target)
        return self._lookup_ip(target)

    # -- domains ----------------------------------------------------------

    def _lookup_domain(self, domain: str) -> AbuseLookup:
        target = domain
        domain = normalise_domain(domain) or ""
        if not domain:
            return AbuseLookup(target)
        base_urls = self._servers_for_domain(domain)
        if not base_urls:
            log.info("No RDAP server known for %s", domain)
            return AbuseLookup(target)
        # Registries only know registered domains, not hosts such as
        # "mail.example.co.uk": strip labels until one is found.
        labels = domain.split(".")
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            data = self._query(base_urls, f"domain/{candidate}")
            if data is not None:
                return AbuseLookup(target, _registered_name(data, candidate),
                                   _organisation(data, "registrar"),
                                   tuple(_abuse_emails(data)))
        return AbuseLookup(target)

    def _servers_for_domain(self, domain: str) -> list[str]:
        """Return the RDAP base URLs of the registry managing *domain*."""
        best: tuple[int, list[str]] = (0, [])
        for suffixes, urls in self._services("dns"):
            for suffix in suffixes:
                suffix = suffix.lower()
                matches = domain == suffix or domain.endswith("." + suffix)
                if matches and len(suffix) > best[0]:
                    best = (len(suffix), urls)
        return best[1]

    # -- IP addresses -----------------------------------------------------

    def _lookup_ip(self, ip: str) -> AbuseLookup:
        address = ipaddress.ip_address(ip)
        base_urls = self._servers_for_ip(address)
        if not base_urls:
            log.info("No RDAP server known for %s", ip)
            return AbuseLookup(ip)
        data = self._query(base_urls, f"ip/{address}")
        if data is None:
            return AbuseLookup(ip)
        return AbuseLookup(ip, str(address),
                           _organisation(data, "registrant"),
                           tuple(_abuse_emails(data)))

    def _servers_for_ip(self, address) -> list[str]:
        """Return the RDAP base URLs of the RIR managing *address*."""
        kind = "ipv4" if address.version == 4 else "ipv6"
        best: tuple[int, list[str]] = (-1, [])
        for prefixes, urls in self._services(kind):
            for prefix in prefixes:
                network = ipaddress.ip_network(prefix, strict=False)
                if address in network and network.prefixlen > best[0]:
                    best = (network.prefixlen, urls)
        return best[1]

    # -- HTTP -------------------------------------------------------------

    def _services(self, kind: str) -> list:
        """Return (and memoise) the ``services`` of an IANA registry."""
        if kind not in self._bootstrap:
            data = self._get_json(IANA_BOOTSTRAP_URLS[kind])
            self._bootstrap[kind] = (data or {}).get("services", [])
        return self._bootstrap[kind]

    def _query(self, base_urls: list[str], path: str) -> dict | None:
        """Query the first HTTPS server answering for *path*."""
        for base_url in base_urls:
            if not base_url.startswith("https://"):
                continue  # Never fall back to clear-text HTTP.
            data = self._get_json(base_url.rstrip("/") + "/" + path)
            if data is not None:
                return data
        return None

    def _get_json(self, url: str) -> dict | None:
        """GET *url* and decode JSON; return ``None`` on any failure."""
        try:
            response = self._session.get(url, headers=_RDAP_HEADERS,
                                         timeout=self._timeout)
        except requests.RequestException as exc:
            log.warning("RDAP request to %s failed: %s", url, exc)
            return None
        if response.status_code == 404:
            return None
        if not response.ok:
            log.warning("RDAP server answered HTTP %s for %s",
                        response.status_code, url)
            return None
        try:
            return response.json()
        except ValueError:
            log.warning("RDAP server sent invalid JSON for %s", url)
            return None


def _walk_entities(entities: list) -> Iterator[dict]:
    """Yield every entity, including nested ones (registrar -> abuse)."""
    for entity in entities or []:
        if isinstance(entity, dict):
            yield entity
            yield from _walk_entities(entity.get("entities"))


def _vcard_emails(entity: dict) -> Iterator[str]:
    """Yield the e-mail addresses of an entity's jCard (RFC 7095)."""
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return
    for item in vcard[1]:
        if (isinstance(item, list) and len(item) == 4
                and item[0] == "email" and isinstance(item[3], str)):
            yield item[3].strip().lower()


def _registered_name(data: dict, queried: str) -> str:
    """Return the domain actually registered, as named by the registry.

    Some registries answer a query for ``host.example.site`` with the
    record of ``example.site``: their ``ldhName`` is the reliable name.
    """
    name = normalise_domain(str(data.get("ldhName") or ""))
    if name and (queried == name or queried.endswith("." + name)):
        return name
    return queried


def _vcard_name(entity: dict) -> str:
    """Return the formatted name (``fn``) of an entity's jCard."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if (isinstance(item, list) and len(item) == 4
                    and item[0] == "fn" and isinstance(item[3], str)):
                return " ".join(item[3].split())
    return ""


def _organisation(data: dict, role: str) -> str:
    """Return the name of the first entity with *role*, or a fallback."""
    for entity in _walk_entities(data.get("entities")):
        if role in (entity.get("roles") or []):
            name = _vcard_name(entity)
            if name:
                return name
    name = data.get("name")
    return name if isinstance(name, str) else ""


def _abuse_emails(data: dict) -> list[str]:
    """Return the e-mail addresses of entities holding the abuse role."""
    emails = (email
              for entity in _walk_entities(data.get("entities"))
              if "abuse" in (entity.get("roles") or [])
              for email in _vcard_emails(entity))
    return [email for email in dict.fromkeys(emails) if "@" in email]
