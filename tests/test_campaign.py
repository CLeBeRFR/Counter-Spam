"""Tests for the reporting strategy: planning, ledger and sending."""

import json
import socket
from unittest import mock

import pytest

from conftest import RAW_SPAM, RAW_UNAUTHENTICATED, FakeRdap, fake_resolver, \
    make_sample
from counter_spam import campaign
from counter_spam.campaign import (DECLARED, LINK_DOMAIN, LINK_HOSTING,
                                   SENDING_DOMAIN, SENDING_SERVER,
                                   CampaignPlanner, Finding, ReportGroup,
                                   ReportLedger, fetch_samples,
                                   resolve_addresses, send_reports)
from counter_spam.graph import GraphError, MessageSummary
from counter_spam.providers import APWG_ADDRESS
from counter_spam.rdap import AbuseLookup


def plan_for(samples, rdap, **options):
    options.setdefault("resolve", fake_resolver)
    return CampaignPlanner(rdap, **options).plan(samples)


def group_by_email(plan):
    return {group.email: group for group in plan.groups}


class TestPlanning:
    def test_one_group_per_abuse_desk(self, samples, fake_rdap):
        groups = group_by_email(plan_for(samples, fake_rdap))
        assert set(groups) == {
            "abuse@edgecast.test", "abuse@microsoft.com",
            "abuse@registrar.test", "abuse@other-registrar.test",
            "abuse@cloudflare.com", APWG_ADDRESS}

    def test_sending_server_goes_to_network_owner(self, samples, fake_rdap):
        group = group_by_email(plan_for(samples, fake_rdap))[
            "abuse@microsoft.com"]
        assert group.entries == {1: [Finding(SENDING_SERVER,
                                             "20.12.182.63")]}
        assert group.policy.form_url  # Microsoft prefers its portal.

    def test_registrar_gets_sending_domain_and_link(self, samples, fake_rdap):
        group = group_by_email(plan_for(samples, fake_rdap))[
            "abuse@registrar.test"]
        assert group.organisation == "Cheap Registrar"
        assert group.entries[0] == [
            Finding(SENDING_DOMAIN, "spam-sender.com"),
            Finding(LINK_DOMAIN, "phish-site.com")]

    def test_hosting_of_advertised_sites(self, samples, fake_rdap):
        group = group_by_email(plan_for(samples, fake_rdap))[
            "abuse@cloudflare.com"]
        assert group.entries == {
            0: [Finding(LINK_HOSTING, "104.16.1.1", "phish-site.com")],
            1: [Finding(LINK_HOSTING, "104.16.1.1", "casino-promo.site")]}

    def test_only_registered_domains_are_resolved(self, samples, fake_rdap):
        resolve = mock.Mock(return_value=[])
        plan_for(samples, fake_rdap, resolve=resolve)
        resolved = sorted(call.args[0] for call in resolve.call_args_list)
        # Never the per-recipient host names found in the links.
        assert resolved == ["casino-promo.site", "phish-site.com"]

    def test_unverified_domains_are_never_looked_up(self, samples,
                                                    fake_rdap):
        plan_for(samples, fake_rdap)
        assert "webassembly.github.io" not in fake_rdap.calls
        assert "forged.example" not in fake_rdap.calls

    def test_each_target_is_looked_up_once(self, fake_rdap):
        samples = [make_sample(RAW_SPAM, f"id-{n}") for n in range(5)]
        plan = plan_for(samples, fake_rdap)
        assert fake_rdap.calls.count("93.184.215.14") == 1
        assert len(group_by_email(plan)["abuse@edgecast.test"].entries) == 5

    def test_links_can_be_disabled(self, samples, fake_rdap):
        groups = group_by_email(plan_for(samples, fake_rdap,
                                         include_links=False,
                                         include_apwg=False))
        assert set(groups) == {"abuse@edgecast.test", "abuse@microsoft.com",
                               "abuse@registrar.test"}

    def test_brand_protection_registrars_are_skipped(self, samples):
        rdap = FakeRdap({
            "login.phish-site.com": AbuseLookup(
                "login.phish-site.com", "phish-site.com", "MarkMonitor Inc.",
                ("abusecomplaints@markmonitor.com",)),
            "104.16.1.1": AbuseLookup("104.16.1.1", "104.16.1.1",
                                      "Cloudflare, Inc.",
                                      ("abuse@cloudflare.com",))})
        groups = group_by_email(plan_for(samples[:1], rdap,
                                         include_apwg=False))
        assert "abusecomplaints@markmonitor.com" not in groups
        # The hosting provider of the advertised site is still reported.
        assert groups["abuse@cloudflare.com"].entries[0] == [
            Finding(LINK_HOSTING, "104.16.1.1", "phish-site.com")]

    def test_declared_contact_is_a_last_resort(self, samples):
        plan = plan_for(samples[:1], FakeRdap({}), resolve=lambda _: [],
                        include_apwg=False)
        assert [group.email for group in plan.groups] == \
            ["abuse@spam-sender.com"]
        assert plan.groups[0].entries[0] == [
            Finding(DECLARED, "abuse@spam-sender.com")]

    def test_declared_contact_ignored_when_real_ones_exist(self, samples,
                                                           fake_rdap):
        groups = group_by_email(plan_for(samples, fake_rdap))
        assert "abuse@spam-sender.com" not in groups

    def test_orphans_are_reported(self):
        sample = make_sample(RAW_UNAUTHENTICATED)
        plan = plan_for([sample], FakeRdap({}), resolve=lambda _: [],
                        include_apwg=False)
        assert plan.groups == []
        assert plan.orphans == [0]

    def test_apwg_group_is_optional_and_last(self, samples, fake_rdap):
        plan = plan_for(samples, fake_rdap)
        apwg = plan.groups[-1]
        assert apwg.email == APWG_ADDRESS and apwg.optional
        assert sorted(apwg.entries) == [0, 1]

    def test_groups_sorted_by_size(self, fake_rdap):
        samples = [make_sample(RAW_SPAM, "a"), make_sample(RAW_SPAM, "b"),
                   make_sample(RAW_UNAUTHENTICATED, "c")]
        plan = plan_for(samples, fake_rdap, include_apwg=False)
        sizes = [len(group.entries) for group in plan.groups]
        assert sizes == sorted(sizes, reverse=True)

    def test_already_reported_messages_are_skipped(self, samples, fake_rdap,
                                                   tmp_path):
        ledger = ReportLedger(tmp_path / "ledger.json")
        ledger.record(samples[1].fingerprint, "abuse@microsoft.com")
        plan = plan_for(samples, fake_rdap, ledger=ledger)
        assert "abuse@microsoft.com" not in group_by_email(plan)
        assert plan.already_reported == 1

    def test_progress_is_reported(self, samples, fake_rdap):
        progress = mock.Mock()
        planner = CampaignPlanner(fake_rdap, resolve=fake_resolver)
        planner.plan(samples, progress)
        labels = {call.args[2] for call in progress.call_args_list}
        assert labels == {"RDAP", "DNS"}


class TestReportGroup:
    def test_id_is_stable_and_url_safe(self):
        group = ReportGroup(email="abuse@example.com")
        assert group.id == ReportGroup(email="abuse@example.com").id
        assert group.id.isalnum() and len(group.id) == 12

    def test_findings_are_not_duplicated(self):
        group = ReportGroup(email="a@b.c")
        group.add(0, Finding(SENDING_SERVER, "1.2.3.4"))
        group.add(0, Finding(SENDING_SERVER, "1.2.3.4"))
        assert group.entries == {0: [Finding(SENDING_SERVER, "1.2.3.4")]}

    def test_display_name_fallbacks(self):
        assert ReportGroup(email="a@b.c").display_name == "a@b.c"
        assert ReportGroup(email="a@b.c", organisation="Org").display_name \
            == "Org"

    def test_finding_description(self):
        assert Finding(LINK_HOSTING, "1.2.3.4", "x.com").describe() == \
            "web site advertised in the message 1.2.3.4 (serving x.com)"


class TestLedger:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "sub" / "ledger.json"
        ledger = ReportLedger(path)
        ledger.record("hash", "abuse@x.test")
        ledger.record("hash", "abuse@x.test")
        ledger.save()
        assert json.loads(path.read_text()) == {"hash": ["abuse@x.test"]}
        assert ReportLedger(path).already_reported("hash", "abuse@x.test")
        assert not ReportLedger(path).already_reported("hash", "other@x")

    def test_corrupt_ledger_is_ignored(self, tmp_path):
        path = tmp_path / "ledger.json"
        path.write_text("{not json")
        assert not ReportLedger(path).already_reported("h", "e")

    def test_in_memory_ledger(self):
        ledger = ReportLedger(None)
        ledger.record("h", "e")
        ledger.save()  # No file, no error.
        assert ledger.already_reported("h", "e")


class TestResolver:
    def test_returns_public_addresses_only(self, monkeypatch):
        infos = [(0, 0, 0, "", ("10.0.0.1", 0)),
                 (0, 0, 0, "", ("104.16.1.1", 0)),
                 (0, 0, 0, "", ("104.16.1.1", 0)),
                 (0, 0, 0, "", ("2606:4700::1", 0, 0, 0)),
                 (0, 0, 0, "", ("104.16.2.2", 0))]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: infos)
        assert resolve_addresses("x.com") == ["104.16.1.1", "2606:4700::1"]

    def test_resolution_failure(self, monkeypatch):
        def fail(*args, **kwargs):
            raise socket.gaierror("no such domain")

        monkeypatch.setattr(socket, "getaddrinfo", fail)
        assert resolve_addresses("x.com") == []


def test_fetch_samples(graph_client):
    graph_client.list_junk_messages.return_value = [
        MessageSummary("m1", "s", "f", "d"),
        MessageSummary("m2", "s", "f", "d")]
    graph_client.get_message_mime.side_effect = [RAW_SPAM,
                                                 RAW_UNAUTHENTICATED]
    progress = mock.Mock()
    samples = fetch_samples(graph_client, 2, progress)
    assert [sample.graph_id for sample in samples] == ["m1", "m2"]
    assert samples[0].evidence.sender_ips == ["93.184.215.14"]
    assert progress.call_count == 2


class TestSending:
    @pytest.fixture
    def plan(self, samples, fake_rdap):
        return plan_for(samples, fake_rdap)

    def test_sends_each_group_and_records_it(self, plan, graph_client,
                                             tmp_path):
        ledger = ReportLedger(tmp_path / "ledger.json")
        groups = [group for group in plan.groups if not group.optional]
        results = send_reports(graph_client, plan, groups, ledger, pause=0)

        assert all(result.ok for result in results)
        assert graph_client.send_mail.call_count == len(groups)
        recipients = {tuple(call.args[0])
                      for call in graph_client.send_mail.call_args_list}
        assert ("abuse@microsoft.com",) in recipients
        assert ReportLedger(tmp_path / "ledger.json").already_reported(
            plan.samples[1].fingerprint, "abuse@microsoft.com")
        graph_client.move_to_deleted_items.assert_not_called()

    def test_attachments_are_the_original_messages(self, plan,
                                                   graph_client):
        group = group_by_email(plan)["abuse@cloudflare.com"]
        send_reports(graph_client, plan, [group], ReportLedger(None),
                     pause=0)
        attachments = graph_client.send_mail.call_args.kwargs["attachments"]
        assert [content for _, content in attachments] == \
            [RAW_SPAM, RAW_UNAUTHENTICATED]

    def test_failures_are_reported_and_not_recorded(self, plan,
                                                    graph_client):
        graph_client.send_mail.side_effect = GraphError(429, "Throttled",
                                                        "slow down")
        ledger = ReportLedger(None)
        group = group_by_email(plan)["abuse@microsoft.com"]
        results = send_reports(graph_client, plan, [group], ledger,
                               pause=0, delete=True)
        assert [result.ok for result in results] == [False]
        assert "Throttled" in results[0].error
        assert not ledger.already_reported(plan.samples[1].fingerprint,
                                           "abuse@microsoft.com")
        graph_client.move_to_deleted_items.assert_not_called()

    def test_delete_moves_only_reported_messages(self, plan, graph_client):
        group = group_by_email(plan)["abuse@microsoft.com"]
        send_reports(graph_client, plan, [group], ReportLedger(None),
                     pause=0, delete=True)
        graph_client.move_to_deleted_items.assert_called_once_with("id-2")

    def test_note_is_included(self, plan, graph_client):
        group = group_by_email(plan)["abuse@microsoft.com"]
        send_reports(graph_client, plan, [group], ReportLedger(None),
                     pause=0, note="Please act quickly.")
        assert "Please act quickly." in graph_client.send_mail.call_args \
            .args[2]

    def test_pause_between_sends(self, plan, graph_client, monkeypatch):
        sleep = mock.Mock()
        monkeypatch.setattr(campaign.time, "sleep", sleep)
        groups = [group for group in plan.groups if not group.optional]
        send_reports(graph_client, plan, groups, ReportLedger(None),
                     pause=1.5)
        assert sleep.call_count == len(groups) - 1
        sleep.assert_called_with(1.5)

    def test_groups_refusing_email_are_skipped(self, plan, graph_client):
        group = group_by_email(plan)["abuse@microsoft.com"]
        group.policy = mock.Mock(accepts_email=False)
        assert send_reports(graph_client, plan, [group],
                            ReportLedger(None), pause=0) == []
        graph_client.send_mail.assert_not_called()


class TestMoreSending:
    def test_move_failure_is_logged_not_raised(self, samples, fake_rdap,
                                               graph_client, caplog):
        plan = plan_for(samples, fake_rdap)
        graph_client.move_to_deleted_items.side_effect = GraphError(
            404, "ErrorItemNotFound", "gone")
        group = group_by_email(plan)["abuse@microsoft.com"]
        results = send_reports(graph_client, plan, [group],
                               ReportLedger(None), pause=0, delete=True)
        assert results[0].ok
        assert "Could not move message" in caplog.text

    def test_ledger_is_saved_after_each_success(self, samples, fake_rdap,
                                                graph_client, tmp_path):
        plan = plan_for(samples, fake_rdap)
        path = tmp_path / "ledger.json"
        groups = [group for group in plan.groups if not group.optional]
        # The second send fails: the first one must already be on disk.
        graph_client.send_mail.side_effect = [None, KeyboardInterrupt]
        with pytest.raises(KeyboardInterrupt):
            send_reports(graph_client, plan, groups, ReportLedger(path),
                         pause=0)
        assert json.loads(path.read_text())


class TestMorePlanning:
    def test_fingerprint_is_content_based(self):
        assert make_sample(RAW_SPAM, "a").fingerprint == \
            make_sample(RAW_SPAM, "b").fingerprint
        assert make_sample(RAW_SPAM).fingerprint != \
            make_sample(RAW_UNAUTHENTICATED).fingerprint

    def test_empty_input(self, fake_rdap):
        plan = plan_for([], fake_rdap)
        assert (plan.groups, plan.orphans, fake_rdap.calls) == ([], [], [])

    def test_several_abuse_addresses_for_one_resource(self, samples):
        rdap = FakeRdap({"20.12.182.63": AbuseLookup(
            "20.12.182.63", "20.12.182.63", "Net",
            ("abuse@net.test", "security@net.test"))})
        groups = group_by_email(plan_for(samples[1:], rdap,
                                         include_links=False))
        assert set(groups) == {"abuse@net.test", "security@net.test"}

    def test_ledger_with_unexpected_content(self, tmp_path):
        path = tmp_path / "ledger.json"
        path.write_text(json.dumps({"h": "not-a-list", "g": ["e"]}))
        ledger = ReportLedger(path)
        assert not ledger.already_reported("h", "n")
        assert ledger.already_reported("g", "e")


def test_apwg_is_not_offered_when_links_are_excluded(samples, fake_rdap):
    plan = plan_for(samples, fake_rdap, include_links=False,
                    include_apwg=True)
    assert APWG_ADDRESS not in group_by_email(plan)
