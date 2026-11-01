"""Tests for the entry point of the stand-alone executables."""

from unittest import mock

import pytest

from counter_spam import cli, launcher


@pytest.fixture
def run_cli(monkeypatch):
    fake = mock.Mock(return_value=cli.EXIT_OK)
    monkeypatch.setattr(cli, "main", fake)
    return fake


@pytest.fixture
def pause(monkeypatch):
    fake = mock.Mock()
    monkeypatch.setattr(launcher, "_pause", fake)
    return fake


def test_double_click_opens_the_interface(run_cli, pause):
    assert launcher.main([]) == cli.EXIT_OK
    run_cli.assert_called_once_with(["gui"])
    pause.assert_not_called()


def test_arguments_are_the_usual_command_line(run_cli, pause):
    launcher.main(["analyze", "-n", "5"])
    run_cli.assert_called_once_with(["analyze", "-n", "5"])


def test_reads_the_process_arguments(run_cli, pause, monkeypatch):
    monkeypatch.setattr("sys.argv", ["counter-spam", "whoami"])
    launcher.main()
    run_cli.assert_called_once_with(["whoami"])


def test_failed_double_click_waits_before_closing(run_cli, pause):
    run_cli.return_value = cli.EXIT_ERROR
    assert launcher.main([]) == cli.EXIT_ERROR
    pause.assert_called_once()


@pytest.mark.parametrize("code", [cli.EXIT_OK, cli.EXIT_INTERRUPTED])
def test_normal_end_closes_at_once(run_cli, pause, code):
    run_cli.return_value = code
    launcher.main([])
    pause.assert_not_called()


def test_command_line_errors_never_wait(run_cli, pause):
    run_cli.return_value = cli.EXIT_ERROR
    launcher.main(["report"])
    pause.assert_not_called()


def test_argparse_exit_becomes_an_exit_code(run_cli, pause):
    run_cli.side_effect = SystemExit(2)
    assert launcher.main(["bogus"]) == 2
    run_cli.side_effect = SystemExit(None)
    assert launcher.main(["--help"]) == 1


def test_pause_waits_for_enter_in_a_console(monkeypatch):
    stdin = mock.Mock()
    stdin.isatty.return_value = True
    monkeypatch.setattr("sys.stdin", stdin)
    with mock.patch("builtins.input") as ask:
        launcher._pause()
    ask.assert_called_once()


def test_pause_never_blocks_without_a_console(monkeypatch):
    stdin = mock.Mock()
    stdin.isatty.return_value = False
    monkeypatch.setattr("sys.stdin", stdin)
    with mock.patch("builtins.input") as ask:
        launcher._pause()
    ask.assert_not_called()


def test_pause_survives_a_closed_input(monkeypatch):
    stdin = mock.Mock()
    stdin.isatty.return_value = True
    monkeypatch.setattr("sys.stdin", stdin)
    with mock.patch("builtins.input", side_effect=EOFError):
        launcher._pause()
