"""Knowledge about how specific abuse desks want to receive reports.

This is plain data so it can be extended without touching the logic.
Only well-documented channels are listed; every other provider simply
receives the report at the abuse address published in RDAP.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderPolicy:
    """Reporting preferences of an abuse desk.

    Attributes:
        name: display name.
        form_url: official web form, when the provider prefers one.
        form_hint: what to select in that form.
        accepts_email: whether e-mail reports are worth sending at all.
    """

    name: str
    form_url: str = ""
    form_hint: str = ""
    accepts_email: bool = True


#: Policies keyed by the abuse address found in RDAP.
KNOWN_PROVIDERS: dict[str, ProviderPolicy] = {
    # Microsoft publishes abuse@microsoft.com in its registry records but
    # recommends the MSRC portal for Azure / Microsoft Online Services.
    "abuse@microsoft.com": ProviderPolicy(
        name="Microsoft (Azure, Outlook)",
        form_url="https://msrc.microsoft.com/report/abuse",
        form_hint="Incident type \"Spam\" (threat type IP address) for "
                  "sending servers, \"Phishing\" (URL) for links."),
    "abuse@cloudflare.com": ProviderPolicy(
        name="Cloudflare",
        form_url="https://abuse.cloudflare.com/",
        form_hint="Choose \"Phishing & Malware\" or \"Spam\"."),
    # The desks below answer e-mail reports with an automatic reply saying
    # that only their web form is processed.
    "network-abuse@google.com": ProviderPolicy(
        name="Google Cloud",
        form_url="https://support.google.com/code/contact/"
                 "cloud_platform_report",
        form_hint="E-mail reports are not processed.",
        accepts_email=False),
    "abuse@dynadot.com": ProviderPolicy(
        name="Dynadot",
        form_url="https://www.dynadot.com/report-abuse",
        form_hint="E-mail reports are not processed.",
        accepts_email=False),
    "abuse-contact@publicdomainregistry.com": ProviderPolicy(
        name="PublicDomainRegistry",
        form_url="https://publicdomainregistry.com/"
                 "process-for-handling-abuse/",
        form_hint="No action is taken until the online form is used.",
        accepts_email=False),
    "abuse@worldstream.nl": ProviderPolicy(
        name="Worldstream",
        form_url="https://www.worldstream.com/en/abuse",
        form_hint="The abuse mailbox is not monitored.",
        accepts_email=False),
}

#: Registrars specialised in protecting the domains of large companies.
#: A domain registered there belongs to an established brand (sendgrid.net,
#: google.com...), not to a spammer: reporting it to the registrar is
#: pointless, the hosting provider is the right recipient.
BRAND_PROTECTION_REGISTRARS = (
    "markmonitor",
    "csc corporate domains",
    "corporation service company",
    "com laude",
    "safenames",
)

#: Anti-Phishing Working Group: accepts phishing e-mails forwarded as
#: attachments (https://apwg.org/reportphishing/).
APWG_ADDRESS = "reportphishing@apwg.org"


def policy_for(email: str) -> ProviderPolicy | None:
    """Return the known policy for an abuse address, if any."""
    return KNOWN_PROVIDERS.get(email.lower())


def is_brand_protection_registrar(organisation: str) -> bool:
    """Tell whether *organisation* is a brand-protection registrar."""
    organisation = organisation.lower()
    return any(name in organisation for name in BRAND_PROTECTION_REGISTRARS)
