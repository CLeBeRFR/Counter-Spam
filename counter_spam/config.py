"""Runtime configuration for Counter-Spam.

Only *non-secret* settings live here.  The Azure application (client) ID
identifies a public client application and is not a secret: no password,
client secret or token is ever read from or written to a configuration
file.

Settings are resolved in this order (first match wins):

1. explicit values (command-line options);
2. environment variables ``COUNTER_SPAM_CLIENT_ID`` / ``COUNTER_SPAM_TENANT``;
3. the JSON file returned by :func:`config_file_path`;
4. built-in defaults (:data:`BUILTIN_CLIENT_ID`, :data:`DEFAULT_TENANT`).
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "counter-spam"

ENV_CLIENT_ID = "COUNTER_SPAM_CLIENT_ID"
ENV_TENANT = "COUNTER_SPAM_TENANT"

#: ``common`` accepts both work/school and personal Microsoft accounts.
DEFAULT_TENANT = "common"

#: Application (client) ID of the Counter-Spam app registration, shipped
#: with the software so that end users only have to sign in.
#:
#: Like those of Thunderbird or the Azure CLI, a public client ID is not a
#: secret: it only names the application on Microsoft's consent screen.
#: The publisher registers the application once (see README, "Publishing")
#: and pastes its ID here.  Users may still override it.
BUILTIN_CLIENT_ID = "f125cda6-98b7-47d0-8920-6e2464eec4f6"

_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
# A tenant is either a well-known alias, a GUID or a verified domain name.
_TENANT_RE = re.compile(
    r"^(common|organizations|consumers"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[a-z0-9-]+(\.[a-z0-9-]+)+)$",
    re.IGNORECASE,
)


class ConfigError(ValueError):
    """Raised when the configuration is missing or invalid."""


def _platform_dir(windows_env: str, macos_subdir: str, xdg_env: str,
                  xdg_default: str) -> Path:
    """Return the per-user base directory matching the OS conventions."""
    if sys.platform == "win32":
        base = os.environ.get(windows_env)
        if base:
            return Path(base)
        return Path.home() / "AppData" / (
            "Local" if windows_env == "LOCALAPPDATA" else "Roaming")
    if sys.platform == "darwin":
        return Path.home() / "Library" / macos_subdir
    return Path(os.environ.get(xdg_env) or Path.home() / xdg_default)


def config_dir() -> Path:
    """Directory holding the (non-secret) configuration file."""
    return _platform_dir("APPDATA", "Application Support",
                         "XDG_CONFIG_HOME", ".config") / APP_NAME


def cache_dir() -> Path:
    """Directory holding the encrypted token cache.

    On Windows this is ``%LOCALAPPDATA%`` rather than ``%APPDATA%``: a
    DPAPI-encrypted blob is bound to the current machine, so it must not
    roam with the user profile.
    """
    return _platform_dir("LOCALAPPDATA", "Caches",
                         "XDG_CACHE_HOME", ".cache") / APP_NAME


def config_file_path() -> Path:
    """Path of the JSON configuration file."""
    return config_dir() / "config.json"


@dataclass(frozen=True)
class Settings:
    """Validated application settings."""

    client_id: str
    tenant: str = DEFAULT_TENANT
    token_cache_path: Path = field(
        default_factory=lambda: cache_dir() / "token_cache.bin")

    @property
    def authority(self) -> str:
        """OAuth 2.0 authority URL for the configured tenant."""
        return f"https://login.microsoftonline.com/{self.tenant}"


def validate_client_id(client_id: str) -> str:
    """Return *client_id* normalised, or raise :class:`ConfigError`."""
    client_id = client_id.strip()
    if not _GUID_RE.match(client_id):
        raise ConfigError(
            f"Invalid client ID {client_id!r}: expected the 'Application "
            "(client) ID' GUID of your Microsoft Entra app registration.")
    return client_id.lower()


def validate_tenant(tenant: str) -> str:
    """Return *tenant* normalised, or raise :class:`ConfigError`."""
    tenant = tenant.strip()
    if not _TENANT_RE.match(tenant):
        raise ConfigError(
            f"Invalid tenant {tenant!r}: use 'common', 'consumers', "
            "'organizations', a tenant GUID or a domain name.")
    return tenant.lower()


def _read_config_file(path: Path) -> dict:
    """Load the JSON configuration file, returning ``{}`` if absent."""
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object.")
    return data


def load_settings(client_id: str | None = None,
                  tenant: str | None = None) -> Settings:
    """Resolve the settings from options, environment and config file.

    Raises:
        ConfigError: if no client ID is configured or a value is invalid.
    """
    file_data = _read_config_file(config_file_path())

    resolved_client_id = (client_id
                          or os.environ.get(ENV_CLIENT_ID)
                          or file_data.get("client_id")
                          or BUILTIN_CLIENT_ID)
    if not resolved_client_id:
        raise ConfigError(
            "This copy of Counter-Spam has no built-in client ID.  The "
            "publisher must set BUILTIN_CLIENT_ID in counter_spam/config.py "
            "(see README, \"Publishing\"), or run:\n"
            "    python -m counter_spam configure --client-id <GUID>\n"
            f"or set the {ENV_CLIENT_ID} environment variable.")

    resolved_tenant = (tenant
                       or os.environ.get(ENV_TENANT)
                       or file_data.get("tenant")
                       or DEFAULT_TENANT)

    return Settings(client_id=validate_client_id(resolved_client_id),
                    tenant=validate_tenant(resolved_tenant))


def save_settings(client_id: str, tenant: str = DEFAULT_TENANT) -> Path:
    """Persist the non-secret settings and return the file path."""
    data = {"client_id": validate_client_id(client_id),
            "tenant": validate_tenant(tenant)}
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    return path
