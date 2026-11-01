"""Tests for the configuration handling."""

from pathlib import Path

import pytest

from counter_spam import config
from counter_spam.config import ConfigError, load_settings, save_settings

CLIENT_ID = "0F1E2D3C-0000-4000-8000-000000000001"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    monkeypatch.delenv(config.ENV_CLIENT_ID, raising=False)
    monkeypatch.delenv(config.ENV_TENANT, raising=False)


def test_missing_client_id_is_explained(monkeypatch):
    monkeypatch.setattr(config, "BUILTIN_CLIENT_ID", "")
    with pytest.raises(ConfigError, match="BUILTIN_CLIENT_ID"):
        load_settings()


def test_builtin_client_id_needs_no_configuration(monkeypatch):
    monkeypatch.setattr(config, "BUILTIN_CLIENT_ID", CLIENT_ID)
    settings = load_settings()
    assert settings.client_id == CLIENT_ID.lower()
    assert settings.tenant == "common"


def test_user_configuration_overrides_builtin_client_id(monkeypatch):
    monkeypatch.setattr(config, "BUILTIN_CLIENT_ID", CLIENT_ID)
    other = "11111111-2222-4333-8444-555555555555"
    save_settings(other)
    assert load_settings().client_id == other


def test_invalid_values_are_rejected():
    with pytest.raises(ConfigError):
        load_settings(client_id="not-a-guid")
    with pytest.raises(ConfigError):
        load_settings(client_id=CLIENT_ID, tenant="evil.com/../x")


def test_precedence_option_then_env_then_file(monkeypatch):
    save_settings(CLIENT_ID, "consumers")
    assert load_settings().tenant == "consumers"
    monkeypatch.setenv(config.ENV_TENANT, "organizations")
    assert load_settings().tenant == "organizations"
    assert load_settings(tenant="contoso.com").tenant == "contoso.com"
    assert load_settings().client_id == CLIENT_ID.lower()


def test_windows_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    # The token cache must not roam: DPAPI blobs are machine-bound.
    assert config.cache_dir() == tmp_path / "Local" / "counter-spam"
    assert config._platform_dir("APPDATA", "", "", "") == \
        Path(tmp_path / "Roaming")


def test_macos_paths(monkeypatch):
    monkeypatch.setattr(config.sys, "platform", "darwin")
    home = Path.home()
    assert config.cache_dir() == home / "Library" / "Caches" / "counter-spam"
    assert config._platform_dir("APPDATA", "Application Support", "", "") \
        == home / "Library" / "Application Support"


def test_linux_paths_follow_xdg(monkeypatch, tmp_path):
    monkeypatch.setattr(config.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert config.cache_dir() == tmp_path / "xdg" / "counter-spam"


def test_windows_without_environment(monkeypatch):
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert config.cache_dir() == \
        Path.home() / "AppData" / "Local" / "counter-spam"


def test_invalid_config_files(tmp_path):
    (tmp_path / "config.json").write_text("{broken")
    with pytest.raises(ConfigError, match="Cannot read"):
        load_settings(client_id=CLIENT_ID)
    (tmp_path / "config.json").write_text("[1, 2]")
    with pytest.raises(ConfigError, match="JSON object"):
        load_settings(client_id=CLIENT_ID)


def test_settings_authority():
    settings = load_settings(client_id=CLIENT_ID, tenant="consumers")
    assert settings.authority == \
        "https://login.microsoftonline.com/consumers"
