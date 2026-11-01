"""Tests for the abuse desk knowledge base."""

import pytest

from counter_spam.providers import (KNOWN_PROVIDERS,
                                    is_brand_protection_registrar,
                                    policy_for)


def test_microsoft_prefers_the_msrc_portal():
    policy = policy_for("Abuse@Microsoft.com")
    assert policy.form_url == "https://msrc.microsoft.com/report/abuse"
    assert policy.accepts_email


def test_unknown_desk_has_no_policy():
    assert policy_for("abuse@example.com") is None


def test_every_form_is_served_over_https():
    assert all(policy.form_url.startswith("https://")
               for policy in KNOWN_PROVIDERS.values() if policy.form_url)


@pytest.mark.parametrize("organisation, expected", [
    ("MarkMonitor Inc.", True),
    ("CSC CORPORATE DOMAINS, INC.", True),
    ("Com Laude", True),
    ("NameCheap, Inc.", False),
    ("", False),
])
def test_brand_protection_registrars(organisation, expected):
    assert is_brand_protection_registrar(organisation) is expected
