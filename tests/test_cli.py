"""Tests for the command-line interface (network and Outlook mocked)."""

import os
import stat
import sys
from unittest import mock

import pytest

from conftest import RAW_SPAM, RAW_UNAUTHENTICATED, FakeRdap, \
    RDAP_ANSWERS, empty_mailbox_mock
from counter_spam import cli, config
from counter_spam.auth import AuthenticationError
from counter_spam.graph import GraphError, MessageSummary

CLIENT_ID = "00000000-0000-0000-0000-000000000001"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Never touch the real configuration, cache or network."""
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path / "config")
    monkeypatch.setattr(cli, "cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(config, "BUILTIN_CLIENT_ID", CLIENT_ID)
    monkeypatch.delenv(config.ENV_CLIENT_ID, raising=False)
    monkeypatch.delenv(config.ENV_TENANT, raising=False)
    monkeypatch.setattr("counter_spam.campaign.time.sleep", lambda _: None)
    monkeypatch.setattr("counter_spam.campaign.resolve_addresses",
                        lambda domain: ["104.16.1.1"])
    monkeypatch.setattr(cli, "RdapClient",
                        lambda: FakeRdap(dict(RDAP_ANSWERS)))


@pytest.fixture
def outlook(monkeypatch):
    """Mock the authenticator and the Graph client used by the CLI."""
    authenticator = mock.Mock()
    authenticator.signed_in_username.return_value = "me@outlook.com"
    authenticator.cache_is_persistent = True
    client = empty_mailbox_mock()
    client.list_junk_messages.return_value = [
        MessageSummary("m1", "Subject 1", "a@b.c", "2026-10-31"),
        MessageSummary("m2", "Subject 2", "d@e.f", "2026-10-30")]
    client.get_message_mime.side_effect = \
        lambda message_id: RAW_SPAM if message_id == "m1" \
        else RAW_UNAUTHENTICATED
    monkeypatch.setattr(cli, "OutlookAuthenticator",
                        mock.Mock(return_value=authenticator))
    monkeypatch.setattr(cli, "GraphMailClient",
                        mock.Mock(return_value=client))
    return authenticator, client


def scopes_requested(authenticator):
    return [call.args[0]
            for call in authenticator.get_access_token.call_args_list]


class TestParser:
    def test_command_is_required(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args([])

    def test_defaults(self):
        args = cli.build_parser().parse_args(["report"])
        assert (args.limit, args.yes, args.delete, args.apwg) == \
            (50, False, False, False)
        assert args.auth_method == "auto"

    @pytest.mark.parametrize("argv", [
        ["list", "-n", "0"], ["gui", "--port", "70000"],
        ["--auth-method", "password", "list"]])
    def test_invalid_values(self, argv):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(argv)


class TestCommands:
    def test_configure(self, tmp_path, capsys):
        other = "11111111-2222-4333-8444-555555555555"
        assert cli.main(["configure", "--client-id", other,
                         "--tenant", "consumers"]) == 0
        assert config.load_settings().client_id == other
        assert "Configuration saved" in capsys.readouterr().out

    def test_list_uses_read_only_scope(self, outlook, capsys):
        authenticator, _ = outlook
        assert cli.main(["list", "-n", "2"]) == 0
        assert scopes_requested(authenticator) == [["Mail.Read"]]
        output = capsys.readouterr().out
        assert "1. 2026-10-31  a@b.c" in output and "Subject 2" in output

    def test_show_by_index_sanitises_output(self, outlook, capsys):
        assert cli.main(["show", "1"]) == 0
        output = capsys.readouterr().out
        assert "Votre compte est bloqué" in output
        assert "hxxps://login[.]phish-site[.]com" in output
        assert "\x1b" not in output

    def test_show_unknown_index(self, outlook, caplog):
        assert cli.main(["show", "9"]) == 1
        assert "No junk message #9" in caplog.text

    def test_analyze_sends_nothing(self, outlook, capsys):
        authenticator, client = outlook
        assert cli.main(["analyze", "-n", "2"]) == 0
        output = capsys.readouterr().out
        assert "2 spam(s) analysed" in output
        assert "Microsoft (Azure, Outlook) <abuse@microsoft.com>" in output
        assert "Preferred form: https://msrc.microsoft.com" in output
        client.send_mail.assert_not_called()
        assert scopes_requested(authenticator) == [["Mail.Read"]]

    def test_report_asks_once_and_can_be_declined(self, outlook,
                                                  monkeypatch, capsys):
        _, client = outlook
        answers = iter(["n"])
        monkeypatch.setattr("builtins.input", lambda _: next(answers))
        assert cli.main(["report", "-n", "2"]) == 0
        assert "Nothing sent." in capsys.readouterr().out
        client.send_mail.assert_not_called()

    def test_report_sends_all_groups_after_one_confirmation(
            self, outlook, monkeypatch, capsys):
        authenticator, client = outlook
        prompts = []
        monkeypatch.setattr("builtins.input",
                            lambda prompt: prompts.append(prompt) or "y")
        assert cli.main(["report", "-n", "2"]) == 0
        assert len(prompts) == 1
        recipients = {call.args[0][0]
                      for call in client.send_mail.call_args_list}
        assert "abuse@microsoft.com" in recipients
        assert "reportphishing@apwg.org" not in recipients  # Opt-in only.
        assert scopes_requested(authenticator)[-1] == ["Mail.Read",
                                                       "Mail.Send"]
        assert "report e-mail(s) sent" in capsys.readouterr().out

    def test_report_yes_apwg_and_delete(self, outlook, monkeypatch):
        authenticator, client = outlook
        monkeypatch.setattr("builtins.input",
                            mock.Mock(side_effect=AssertionError("asked")))
        assert cli.main(["report", "-y", "--apwg", "--delete"]) == 0
        recipients = {call.args[0][0]
                      for call in client.send_mail.call_args_list}
        assert "reportphishing@apwg.org" in recipients
        assert scopes_requested(authenticator)[-1] == ["Mail.ReadWrite",
                                                       "Mail.Send"]
        assert client.move_to_deleted_items.call_count == 2

    def test_report_twice_sends_nothing_new(self, outlook, monkeypatch,
                                            capsys):
        _, client = outlook
        assert cli.main(["report", "-y"]) == 0
        sent = client.send_mail.call_count
        assert cli.main(["report", "-y"]) == 0
        assert client.send_mail.call_count == sent
        assert "Nothing to send." in capsys.readouterr().out

    def test_report_failure_exit_code(self, outlook):
        _, client = outlook
        client.send_mail.side_effect = GraphError(500, "x", "down")
        assert cli.main(["report", "-y"]) == 1

    def test_report_eof_on_confirmation(self, outlook, monkeypatch):
        _, client = outlook

        def eof(_):
            raise EOFError

        monkeypatch.setattr("builtins.input", eof)
        assert cli.main(["report"]) == 0
        client.send_mail.assert_not_called()

    def test_save_eml(self, outlook, tmp_path):
        target = tmp_path / "eml"
        assert cli.main(["analyze", "--save-eml", str(target)]) == 0
        files = sorted(target.iterdir())
        assert len(files) == 2
        assert all(file.name.startswith("spam-") and file.suffix == ".eml"
                   for file in files)
        if os.name == "posix":
            mode = stat.S_IMODE(files[0].stat().st_mode)
            assert mode == 0o600

    def test_login(self, outlook, capsys):
        assert cli.main(["login"]) == 0
        output = capsys.readouterr().out
        assert "Signed in as me@outlook.com." in output
        assert "Junk folder verified" in output

    def test_whoami_and_logout(self, outlook, capsys):
        authenticator, _ = outlook
        authenticator.logout.return_value = 1
        assert cli.main(["whoami"]) == 0
        assert cli.main(["logout"]) == 0
        output = capsys.readouterr().out
        assert "Signed in as me@outlook.com." in output
        assert "Removed 1 cached account(s)." in output

    def test_gui_signs_in_then_runs_server(self, outlook, monkeypatch):
        run = mock.Mock()
        monkeypatch.setattr("counter_spam.webui.run", run)
        assert cli.main(["gui", "--no-browser", "--port", "0"]) == 0
        assert run.call_args.kwargs["open_browser"] is False


class TestErrors:
    def test_authentication_error(self, outlook, caplog):
        authenticator, _ = outlook
        authenticator.get_access_token.side_effect = \
            AuthenticationError("denied")
        assert cli.main(["list"]) == 1
        assert "denied" in caplog.text

    def test_invalid_client_id(self, caplog):
        assert cli.main(["--client-id", "nope", "whoami"]) == 1
        assert "Invalid client ID" in caplog.text

    def test_keyboard_interrupt(self, outlook, capsys):
        _, client = outlook
        client.list_junk_messages.side_effect = KeyboardInterrupt
        assert cli.main(["list"]) == 130


def test_output_is_robust_to_legacy_consoles(monkeypatch):
    stream = mock.Mock()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", stream)
    cli._configure_output(0)
    stream.reconfigure.assert_called_with(errors="replace")


class TestMoreCommands:
    def test_show_by_message_id(self, outlook, capsys):
        _, client = outlook
        assert cli.main(["show", "m2"]) == 0
        client.get_message_mime.assert_called_with("m2")
        client.list_junk_messages.assert_not_called()
        assert "Bonus 400 %" in capsys.readouterr().out

    def test_empty_junk_folder(self, outlook, capsys):
        _, client = outlook
        client.list_junk_messages.return_value = []
        assert cli.main(["list"]) == 0
        assert cli.main(["analyze"]) == 0
        output = capsys.readouterr().out
        assert "The Junk folder is empty." in output
        assert "0 spam(s) analysed" in output

    def test_orphans_are_listed(self, outlook, monkeypatch, capsys):
        monkeypatch.setattr(cli, "RdapClient", lambda: FakeRdap({}))
        monkeypatch.setattr("counter_spam.campaign.resolve_addresses",
                            lambda domain: [])
        _, client = outlook
        client.list_junk_messages.return_value = [
            MessageSummary("m2", "s", "f", "d")]
        assert cli.main(["report", "--no-links"]) == 0
        output = capsys.readouterr().out
        assert "No abuse contact found for: Bonus 400 %" in output
        assert "Nothing to send." in output

    def test_no_links_option(self, outlook, capsys):
        assert cli.main(["analyze", "--no-links"]) == 0
        output = capsys.readouterr().out
        assert "abuse@cloudflare.com" not in output
        assert "abuse@microsoft.com" in output

    def test_warnings_without_encrypted_storage(self, outlook, capsys):
        authenticator, _ = outlook
        authenticator.cache_is_persistent = False
        assert cli.main(["login"]) == 0
        assert cli.main(["whoami"]) == 0
        output = capsys.readouterr().out
        assert "sign-in will not be remembered" in output
        assert "no encrypted token storage available" in output

    def test_whoami_signed_out(self, outlook, capsys):
        authenticator, _ = outlook
        authenticator.signed_in_username.return_value = None
        assert cli.main(["whoami"]) == 0
        assert "Not signed in." in capsys.readouterr().out

    def test_login_with_extra_consents(self, outlook):
        authenticator, _ = outlook
        assert cli.main(["login", "--send", "--delete"]) == 0
        assert scopes_requested(authenticator) == [["Mail.ReadWrite",
                                                    "Mail.Send"]]

    def test_report_note_reaches_the_reports(self, outlook):
        _, client = outlook
        assert cli.main(["report", "-y", "--note", "Second notice."]) == 0
        assert all("Second notice." in call.args[2]
                   for call in client.send_mail.call_args_list)

    def test_network_error_exit_code(self, outlook, caplog):
        import requests

        _, client = outlook
        client.list_junk_messages.side_effect = \
            requests.ConnectionError("offline")
        assert cli.main(["list"]) == 1
        assert "offline" in caplog.text

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["--version"])
        assert excinfo.value.code == 0
        assert "2.0.0" in capsys.readouterr().out


class TestHelpers:
    def test_sign_in_instructions_go_to_stderr(self, capsys):
        cli._notify_sign_in("Go to https://microsoft.com/devicelogin")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "devicelogin" in captured.err

    def test_progress_line(self, capsys):
        cli._progress(1, 2, "RDAP")
        cli._progress(2, 2, "RDAP")
        cli._progress(0, 0, "nothing")
        assert capsys.readouterr().err == "\rRDAP 1/2\rRDAP 2/2\n"

    def test_output_strips_control_characters(self, capsys):
        cli._out("evil\x1b]52;c;x\x07 text")
        assert capsys.readouterr().out == "evil]52;c;x text\n"

    def test_save_eml_names_come_from_content_only(self, tmp_path):
        first = cli._save_eml(tmp_path, b"Subject: ../../etc/passwd\r\n\r\n")
        second = cli._save_eml(tmp_path, b"Subject: ../../etc/passwd\r\n\r\n")
        assert first == second
        assert first.parent == tmp_path
        assert first.read_bytes().startswith(b"Subject")

    @pytest.mark.parametrize("answer, expected", [
        ("y", True), ("YES", True), (" yes ", True),
        ("", False), ("n", False), ("oui", False)])
    def test_confirm(self, monkeypatch, answer, expected):
        monkeypatch.setattr("builtins.input", lambda _: answer)
        assert cli._confirm("?") is expected


def test_module_entry_point(monkeypatch):
    import runpy

    monkeypatch.setattr(sys, "argv", ["counter_spam", "--version"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("counter_spam", run_name="__main__")
    assert excinfo.value.code == 0


@pytest.mark.parametrize("value, expected", [
    ("20.12.182.63", "20.12.182.63"),
    ("2a00:1450::1", "2a00:1450::1"),
    ("evil.com", "evil[.]com"),
])
def test_display_resource(value, expected):
    assert cli._display_resource(value) == expected


def test_learned_policies_change_the_plan(outlook, capsys):
    from counter_spam.graph import ReceivedMessage

    _, client = outlook
    client.list_sent_conversations.return_value = {
        "c1": ["abuse@microsoft.com"], "c2": ["abuse@edgecast.test"]}
    client.list_replies.return_value = [
        ReceivedMessage("r1", "c1", "abuse@microsoft.com", "Auto", "d"),
        ReceivedMessage("r2", "c2", "postmaster@outlook.com",
                        "Undeliverable: Abuse report", "d")]
    client.get_message_text.side_effect = {
        "r1": "We do not accept reports by e-mail: use our web form "
              "https://msrc.microsoft.com/report/abuse",
        "r2": "Delivery to abuse@edgecast.test failed."}.__getitem__
    assert cli.main(["report", "-y"]) == 0
    output = capsys.readouterr().out
    assert "Learned from a reply: abuse@microsoft.com asks for its web " \
        "form (https://msrc.microsoft.com/report/abuse)" in output
    assert "abuse@edgecast.test address bounced" in output
    assert "No e-mail: use the web form https://msrc.microsoft.com" in output
    assert "No e-mail: the address does not accept e-mails" in output
    recipients = {call.args[0][0] for call in client.send_mail.call_args_list}
    assert "abuse@microsoft.com" not in recipients
    assert "abuse@edgecast.test" not in recipients
    assert recipients  # The other desks are still reported.


def test_reply_analysis_failure_is_only_a_warning(outlook, caplog):
    _, client = outlook
    client.list_sent_conversations.side_effect = GraphError(500, "x", "down")
    assert cli.main(["analyze"]) == 0
    assert "Could not analyse the replies" in caplog.text
