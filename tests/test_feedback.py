"""Tests for the learning from the abuse desks' replies."""

import json
from unittest import mock

import pytest

from counter_spam.feedback import (BOUNCED, FORM, LearnedPolicy, PolicyStore,
                                   classify_reply, find_form_url,
                                   learn_from_replies, policy_lookup)
from counter_spam.graph import ReceivedMessage
from counter_spam.providers import ProviderPolicy

TODAY = "2026-11-01"


def reply(sender="abuse@desk.example", subject="Auto-Reply: Abuse report: 2"):
    return ReceivedMessage("r1", "c1", sender, subject, "2026-11-01T20:30Z")


# Texts modelled on real automatic replies received for Counter-Spam reports.
WORLDSTREAM = """Please be advised that this mailbox is not actively
monitored, and submissions sent to this address will not be processed.
Abuse complaints must be submitted through the webform available on our
website: https://www.worldstream.com/en/abuse
Requests: https://www.internationalerechtshulp.nl/service-english"""
PDR = """This is an automated email. To report a violation of our Terms of
Service, please access our online reporting form at
https://publicdomainregistry.com/process-for-handling-abuse/, select the
appropriate issue. No action will be taken on your issue until you have
entered the report using our online reporting form."""
GOOGLE = """If you would like to report suspected Spam, Malware, Phishing,
or other abuse on Google Cloud, please fill out the form at the following
link: https://support.google.com/code/contact/cloud_platform_report
Legal requests: http://support.google.com/legal"""
CENTRALNIC = """This email address is no longer monitored. To report abusive
use of a domain name, please use our abuse reporting form:
https://abuse.cleandns.space/keysystems
Inaccuracy reports: https://icann-nsp.my.site.com/compliance/s/registration
Contact the registrant: http://www.domain-contact.com"""
DYNADOT = """Please note that we do not accept, nor monitor, abuse reports
via email, and we do require a formal complaint to be submitted via our
webform: https://www.dynadot.com/report-abuse
Registrant Contact Request form: https://www.dynadot.com/domain/contact-request
Support: https://www.dynadot.com/community/contact"""
NAMECHEAP_TICKET = """Thank you for contacting the Namecheap Legal & Abuse
Department. Your ticket NC-HPA-1601 has been created; our team will review
your report and reply as soon as possible."""


class TestClassification:
    @pytest.mark.parametrize("abuse_email, sender, text, form_url", [
        ("abuse@worldstream.nl", "abuse@worldstream.com", WORLDSTREAM,
         "https://www.worldstream.com/en/abuse"),
        ("abuse-contact@publicdomainregistry.com",
         "noreply@publicdomainregistry.com", PDR,
         "https://publicdomainregistry.com/process-for-handling-abuse/"),
        ("network-abuse@google.com", "network-abuse@google.com", GOOGLE,
         "https://support.google.com/code/contact/cloud_platform_report"),
        ("abuse@key-systems.net", "abuse@key-systems.net", CENTRALNIC,
         "https://abuse.cleandns.space/keysystems"),
        ("abuse@dynadot.com", "abuse@dynadot.com", DYNADOT,
         "https://www.dynadot.com/report-abuse"),
    ])
    def test_web_form_auto_replies(self, abuse_email, sender, text,
                                   form_url):
        policy = classify_reply(abuse_email, reply(sender), text, TODAY)
        assert policy == LearnedPolicy(abuse_email, FORM, form_url, TODAY,
                                       sender)

    def test_ticket_confirmation_means_email_works(self):
        assert classify_reply("abuse@namecheap.com",
                              reply("abuse@namecheap.com"),
                              NAMECHEAP_TICKET, TODAY) is None

    def test_refusal_without_link(self):
        policy = classify_reply("abuse@x.example", reply(),
                                "This mailbox is not monitored.", TODAY)
        assert policy.status == FORM and policy.form_url == ""

    def test_form_mention_without_trusted_link_is_not_enough(self):
        text = "You may also use our web form at https://evil.test/form"
        assert classify_reply("abuse@x.example", reply(), text,
                              TODAY) is None

    @pytest.mark.parametrize("subject, sender", [
        ("Undeliverable: Abuse report: 1 unsolicited e-mail",
         "postmaster@outlook.com"),
        ("Mail delivery failed: returning message to sender",
         "mailer-daemon@mx.example"),
        ("Delivery Status Notification (Failure)", "x@y.example"),
        ("Non remis : Abuse report", "postmaster@outlook.fr"),
    ])
    def test_bounces(self, subject, sender):
        text = "Delivery to hm-changed@vnnic.vn failed: user unknown."
        policy = classify_reply("hm-changed@vnnic.vn",
                                reply(sender, subject), text, TODAY)
        assert policy == LearnedPolicy("hm-changed@vnnic.vn", BOUNCED, "",
                                       TODAY, sender)

    def test_bounce_about_another_recipient_is_ignored(self):
        assert classify_reply(
            "abuse@a.example",
            reply("postmaster@outlook.com", "Undeliverable: Abuse report"),
            "Delivery to abuse@b.example failed.", TODAY) is None


class TestFormLinks:
    @pytest.mark.parametrize("text, expected", [
        # Same organisation, other TLD.
        ("https://www.worldstream.com/en/abuse", "https://www.worldstream"
                                                 ".com/en/abuse"),
        # Plain HTTP is never trusted.
        ("http://worldstream.nl/abuse", ""),
        # Look-alike domains are rejected.
        ("https://worldstream.nl.evil.test/abuse", ""),
        ("https://worldstream-abuse.test/form", ""),
        # Recognised abuse platforms are accepted.
        ("https://abuse.cleandns.space/x", "https://abuse.cleandns.space/x"),
        # Trailing punctuation is dropped.
        ("Form: https://worldstream.nl/abuse.",
         "https://worldstream.nl/abuse"),
        ("no link at all", ""),
    ])
    def test_trust_rules(self, text, expected):
        assert find_form_url(text, "abuse@worldstream.nl",
                             "abuse@worldstream.com") == expected

    def test_abuse_links_are_preferred(self):
        text = ("Support: https://desk.example/contact "
                "Abuse: https://desk.example/report-abuse")
        assert find_form_url(text, "abuse@desk.example", "") == \
            "https://desk.example/report-abuse"

    def test_country_code_second_level_domains(self):
        assert find_form_url("https://www.host.co.uk/abuse",
                             "abuse@host.co.uk", "") == \
            "https://www.host.co.uk/abuse"
        assert find_form_url("https://evil.co.uk/abuse",
                             "abuse@host.co.uk", "") == ""


class TestStore:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "providers.json"
        store = PolicyStore(path)
        assert store.learn(LearnedPolicy("Abuse@X.example", FORM,
                                         "https://x.example/f", TODAY))
        store.mark_processed("reply-1")
        store.save()
        loaded = PolicyStore(path)
        assert loaded.get("abuse@x.example").form_url == \
            "https://x.example/f"
        assert loaded.was_processed("reply-1")
        assert json.loads(path.read_text())["policies"][0]["email"] == \
            "abuse@x.example"

    def test_known_link_is_kept_when_a_later_reply_has_none(self):
        store = PolicyStore(None)
        store.learn(LearnedPolicy("a@x.example", FORM, "https://x.example/f"))
        assert not store.learn(LearnedPolicy("a@x.example", FORM, ""))
        assert store.get("a@x.example").form_url == "https://x.example/f"

    def test_forget(self):
        store = PolicyStore(None)
        store.learn(LearnedPolicy("a@x.example", BOUNCED))
        store.forget("A@x.example")
        assert store.get("a@x.example") is None

    def test_corrupt_files_are_ignored(self, tmp_path):
        path = tmp_path / "providers.json"
        path.write_text("{broken")
        assert PolicyStore(path).all() == []
        path.write_text(json.dumps({"policies": [{"unexpected": 1}]}))
        assert PolicyStore(path).all() == []


class TestLookup:
    def test_learned_policy_overrides_default(self):
        store = PolicyStore(None)
        store.learn(LearnedPolicy("abuse@unknown.example", FORM,
                                  "https://unknown.example/abuse", TODAY))
        policy = policy_lookup(store)("abuse@unknown.example", "Unknown Inc")
        assert policy == ProviderPolicy(
            "Unknown Inc", "https://unknown.example/abuse",
            f"Learned from their automatic reply of {TODAY}: e-mails are "
            "not processed.", accepts_email=False)

    def test_known_form_is_kept_when_reply_has_no_link(self):
        store = PolicyStore(None)
        store.learn(LearnedPolicy("abuse@microsoft.com", FORM, "", TODAY))
        policy = policy_lookup(store)("abuse@microsoft.com", "")
        assert policy.name == "Microsoft (Azure, Outlook)"
        assert policy.form_url == "https://msrc.microsoft.com/report/abuse"
        assert not policy.accepts_email

    def test_bounced_address(self):
        store = PolicyStore(None)
        store.learn(LearnedPolicy("hm-changed@vnnic.vn", BOUNCED, "", TODAY))
        policy = policy_lookup(store)("hm-changed@vnnic.vn", "VNNIC")
        assert not policy.accepts_email and policy.form_url == ""
        assert "bounced" in policy.form_hint

    def test_without_learning_known_policies_apply(self):
        lookup = policy_lookup(PolicyStore(None))
        assert lookup("abuse@dynadot.com", "").accepts_email is False
        assert lookup("abuse@unknown.example", "") is None


class TestLearnFromReplies:
    def make_client(self, replies, texts):
        client = mock.Mock()
        client.list_sent_conversations.return_value = {
            "c-dyn": ["abuse@dynadot.com"],
            "c-nc": ["abuse@namecheap.com"],
            "c-ws": ["abuse@worldstream.nl"]}
        client.list_replies.return_value = replies
        client.get_message_text.side_effect = texts.__getitem__
        return client

    def test_learns_and_remembers_processed_replies(self, tmp_path):
        replies = [
            ReceivedMessage("r1", "c-dyn", "abuse@dynadot.com",
                            "Auto-Reply: Abuse report", "d"),
            ReceivedMessage("r2", "c-nc", "abuse@namecheap.com",
                            "[NC-HPA-1601] Abuse report", "d"),
            ReceivedMessage("r3", "c-ws", "abuse@worldstream.com",
                            "[Worldstream] Abuse Auto-reply", "d")]
        client = self.make_client(replies, {"r1": DYNADOT,
                                            "r2": NAMECHEAP_TICKET,
                                            "r3": WORLDSTREAM})
        store = PolicyStore(tmp_path / "providers.json")
        progress = mock.Mock()

        learned = learn_from_replies(client, store, "Abuse report:",
                                     progress)

        assert sorted(policy.email for policy in learned) == \
            ["abuse@dynadot.com", "abuse@worldstream.nl"]
        assert store.get("abuse@namecheap.com") is None
        client.list_sent_conversations.assert_called_once_with(
            "Abuse report:")
        assert progress.call_count == 3

        # Second run: replies already processed are not downloaded again.
        client.get_message_text.reset_mock()
        again = learn_from_replies(client, PolicyStore(
            tmp_path / "providers.json"), "Abuse report:")
        assert again == []
        client.get_message_text.assert_not_called()

    def test_no_sent_report(self):
        client = mock.Mock()
        client.list_sent_conversations.return_value = {}
        client.list_replies.return_value = []
        assert learn_from_replies(client, PolicyStore(None),
                                  "Abuse report:") == []
