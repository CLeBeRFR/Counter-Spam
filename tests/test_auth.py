"""Tests for the authentication layer (MSAL mocked)."""

from pathlib import Path
from unittest import mock

import pytest

from counter_spam import auth
from counter_spam.auth import (AuthenticationError, OutlookAuthenticator,
                               required_scopes)
from counter_spam.config import Settings

CLIENT_ID = "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(client_id=CLIENT_ID,
                    token_cache_path=tmp_path / "cache" / "tokens.bin")


@pytest.fixture
def msal_app(monkeypatch):
    app = mock.Mock()
    monkeypatch.setattr(auth.msal, "PublicClientApplication",
                        mock.Mock(return_value=app))
    return app


def test_scopes_follow_least_privilege():
    assert required_scopes() == ["Mail.Read"]
    assert required_scopes(send=True) == ["Mail.Read", "Mail.Send"]
    assert required_scopes(send=True, delete=True) == \
        ["Mail.ReadWrite", "Mail.Send"]


def test_cache_falls_back_to_memory_when_no_encryption(monkeypatch,
                                                       settings, msal_app):
    def unavailable(_location):
        raise RuntimeError("no keyring")

    monkeypatch.setattr(auth, "build_encrypted_persistence", unavailable)
    authenticator = OutlookAuthenticator(settings)

    assert authenticator.cache_is_persistent is False
    assert not settings.token_cache_path.exists()


def test_cached_token_is_used_silently(settings, msal_app, monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = [{"username": "me@outlook.com"}]
    msal_app.acquire_token_silent.return_value = {"access_token": "AT"}

    token = OutlookAuthenticator(settings).get_access_token(["Mail.Read"])

    assert token == "AT"
    msal_app.initiate_device_flow.assert_not_called()


def test_device_code_flow_when_not_signed_in(settings, msal_app,
                                             monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    msal_app.initiate_device_flow.return_value = {
        "user_code": "ABCD", "message": "Go to https://microsoft.com/..."}
    msal_app.acquire_token_by_device_flow.return_value = {
        "access_token": "AT"}
    shown = []

    authenticator = OutlookAuthenticator(settings, method="device",
                                         notify=shown.append)
    assert authenticator.get_access_token(["Mail.Read"]) == "AT"
    assert shown == ["Go to https://microsoft.com/..."]


def test_non_interactive_mode_never_prompts(settings, msal_app,
                                            monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    authenticator = OutlookAuthenticator(settings)
    with pytest.raises(AuthenticationError):
        authenticator.get_access_token(["Mail.Read"], interactive=False)
    msal_app.initiate_device_flow.assert_not_called()


def test_failed_sign_in_raises(settings, msal_app, monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    msal_app.initiate_device_flow.return_value = {
        "user_code": "X", "message": "m"}
    msal_app.acquire_token_by_device_flow.return_value = {
        "error": "expired_token", "error_description": "Code expired"}
    with pytest.raises(AuthenticationError, match="Code expired"):
        OutlookAuthenticator(settings, method="device",
                             notify=lambda _: None) \
            .get_access_token(["Mail.Read"])


@pytest.mark.parametrize("platform, env, expected", [
    ("linux", {"DISPLAY": ":0"}, "browser"),
    ("linux", {"WAYLAND_DISPLAY": "wayland-0"}, "browser"),
    ("linux", {}, "device"),
    ("linux", {"DISPLAY": ":0", "SSH_CONNECTION": "1 2 3 4"}, "device"),
    ("win32", {}, "browser"),
    ("darwin", {}, "browser"),
])
def test_auto_method_picks_browser_only_with_a_screen(
        monkeypatch, settings, msal_app, platform, env, expected):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    monkeypatch.setattr(auth.sys, "platform", platform)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert OutlookAuthenticator(settings)._method == expected


def test_browser_flow_uses_msal_interactive(settings, msal_app,
                                            monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    msal_app.acquire_token_interactive.return_value = {"access_token": "AT"}
    authenticator = OutlookAuthenticator(settings, method="browser",
                                         notify=lambda _: None)
    assert authenticator.get_access_token(["Mail.Read"]) == "AT"
    msal_app.initiate_device_flow.assert_not_called()


@pytest.fixture
def signed_in(settings, msal_app, monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = [{"username": "me@outlook.com"},
                                          {"username": "other@outlook.com"}]
    return OutlookAuthenticator(settings, method="device",
                                notify=lambda _: None)


def test_unknown_method_is_rejected(settings, msal_app):
    with pytest.raises(ValueError):
        OutlookAuthenticator(settings, method="password")


def test_encrypted_cache_is_used_when_available(monkeypatch, settings,
                                                msal_app):
    persistence = mock.Mock()
    monkeypatch.setattr(auth, "build_encrypted_persistence",
                        mock.Mock(return_value=persistence))
    monkeypatch.setattr(auth, "PersistedTokenCache",
                        mock.Mock(return_value="CACHE"))
    authenticator = OutlookAuthenticator(settings)
    assert authenticator.cache_is_persistent is True
    auth.build_encrypted_persistence.assert_called_once_with(
        str(settings.token_cache_path))
    auth.PersistedTokenCache.assert_called_once_with(persistence)
    assert settings.token_cache_path.parent.is_dir()


def test_authority_and_client_id_are_passed_to_msal(settings, msal_app,
                                                    monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    OutlookAuthenticator(settings)
    call = auth.msal.PublicClientApplication.call_args
    assert call.args == (CLIENT_ID,)
    assert call.kwargs["authority"] == \
        "https://login.microsoftonline.com/common"


def test_first_cached_account_is_used(signed_in, msal_app):
    msal_app.acquire_token_silent.return_value = {"access_token": "AT"}
    assert signed_in.get_access_token(["Mail.Read"]) == "AT"
    assert msal_app.acquire_token_silent.call_args.kwargs["account"] == \
        {"username": "me@outlook.com"}
    assert signed_in.signed_in_username() == "me@outlook.com"


def test_new_scope_triggers_interactive_consent(signed_in, msal_app):
    msal_app.acquire_token_silent.return_value = {
        "error": "interaction_required"}
    msal_app.initiate_device_flow.return_value = {"user_code": "X",
                                                  "message": "m"}
    msal_app.acquire_token_by_device_flow.return_value = {
        "access_token": "AT2"}
    assert signed_in.get_access_token(["Mail.Send"]) == "AT2"
    assert msal_app.initiate_device_flow.call_args.kwargs["scopes"] == \
        ["Mail.Send"]


def test_device_flow_start_failure(settings, msal_app, monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    msal_app.initiate_device_flow.return_value = {
        "error": "unauthorized_client",
        "error_description": "not enabled for consumers"}
    with pytest.raises(AuthenticationError, match="consumers"):
        OutlookAuthenticator(settings, method="device") \
            .get_access_token(["Mail.Read"])


def test_token_provider_fetches_a_token_per_call(signed_in, msal_app):
    msal_app.acquire_token_silent.side_effect = [
        {"access_token": "T1"}, {"access_token": "T2"}]
    provider = signed_in.token_provider(("Mail.Read",))
    assert (provider(), provider()) == ("T1", "T2")


def test_logout_removes_every_account(signed_in, msal_app):
    assert signed_in.logout() == 2
    assert msal_app.remove_account.call_count == 2


def test_no_account_means_no_username(settings, msal_app, monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    assert OutlookAuthenticator(settings).signed_in_username() is None


def test_missing_result_raises(signed_in):
    with pytest.raises(AuthenticationError, match="unknown error"):
        signed_in._extract_access_token(None)


def test_signed_in_name_comes_from_id_token(signed_in, msal_app):
    msal_app.acquire_token_silent.return_value = {
        "access_token": "AT", "id_token_claims": {"name": "Marie Dupont"}}
    assert signed_in.signed_in_name() == "Marie Dupont"
    msal_app.acquire_token_silent.return_value = None
    assert signed_in.signed_in_name() == ""


def test_signed_in_name_without_account(settings, msal_app, monkeypatch):
    monkeypatch.setattr(auth, "_build_token_cache",
                        lambda _: (mock.Mock(), True))
    msal_app.get_accounts.return_value = []
    assert OutlookAuthenticator(settings).signed_in_name() == ""
