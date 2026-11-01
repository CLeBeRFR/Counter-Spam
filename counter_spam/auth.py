"""Authentication against Outlook through the Microsoft identity platform.

Security design
---------------
* **OAuth 2.0 / OpenID Connect, no password handling.**  The user signs in
  on Microsoft's own page, either through the *device code* flow (works in
  any terminal, including over SSH) or through the *authorization code
  flow with PKCE* in the system browser.  The password never reaches this
  program, and MFA / conditional access policies keep applying.
* **Public client, no client secret.**  A desktop tool cannot keep a
  secret confidential, so none is used.
* **Least privilege.**  Each command requests only the delegated Microsoft
  Graph scopes it needs (see :func:`required_scopes`); extra permissions
  are consented to incrementally, the first time they are needed.
* **Encrypted token cache.**  Refresh tokens are stored with the operating
  system's protection: DPAPI on Windows, Keychain on macOS and libsecret
  (GNOME Keyring / KWallet) on Linux.  When no such backend is available
  the cache is kept in memory only; it is never written in clear text.
* **Tokens are never printed nor logged.**
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Callable, Iterable, Sequence

import msal
from msal_extensions import PersistedTokenCache, build_encrypted_persistence

from .config import Settings

log = logging.getLogger(__name__)

# Delegated Microsoft Graph permissions.
MAIL_READ = "Mail.Read"
MAIL_READ_WRITE = "Mail.ReadWrite"
MAIL_SEND = "Mail.Send"

AUTH_METHODS = ("auto", "browser", "device")


class AuthenticationError(RuntimeError):
    """Raised when no access token could be obtained."""


def required_scopes(*, send: bool = False, delete: bool = False) -> list[str]:
    """Return the minimal list of scopes for the requested capabilities.

    Args:
        send: the caller needs to send e-mails (abuse reports).
        delete: the caller needs to move messages to *Deleted Items*.
    """
    # Mail.ReadWrite is a superset of Mail.Read: never request both.
    scopes = [MAIL_READ_WRITE if delete else MAIL_READ]
    if send:
        scopes.append(MAIL_SEND)
    return scopes


def has_graphical_session() -> bool:
    """Tell whether a local browser window can be shown to the user."""
    if sys.platform in ("win32", "darwin"):
        return not os.environ.get("SSH_CONNECTION")
    has_display = bool(os.environ.get("DISPLAY")
                       or os.environ.get("WAYLAND_DISPLAY"))
    return has_display and not os.environ.get("SSH_CONNECTION")


def _build_token_cache(settings: Settings) -> tuple[msal.TokenCache, bool]:
    """Create the token cache and tell whether it is persisted on disk.

    Returns:
        A ``(cache, is_persistent)`` tuple.
    """
    path = settings.token_cache_path
    try:
        # 0o700 is honoured on POSIX and harmlessly ignored on Windows,
        # where the per-user %LOCALAPPDATA% ACLs already apply.
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        persistence = build_encrypted_persistence(str(path))
        return PersistedTokenCache(persistence), True
    except Exception as exc:  # Each OS backend raises its own errors.
        # Fail closed: keep tokens in memory rather than in clear text.
        log.warning(
            "Encrypted token storage is unavailable (%s). Tokens will be "
            "kept in memory only and you will have to sign in again at "
            "each run.", exc)
        return msal.SerializableTokenCache(), False


class OutlookAuthenticator:
    """Obtain and cache Microsoft Graph access tokens for one user.

    Args:
        settings: validated application settings.
        method: interactive flow to use when no cached token is usable:
            ``"browser"`` (system browser), ``"device"`` (one-time code to
            enter on any device) or ``"auto"`` (default: browser when a
            graphical session is available, device code otherwise).
        notify: callable used to show the sign-in instructions to the user.
    """

    def __init__(self, settings: Settings, *, method: str = "auto",
                 notify: Callable[[str], None] = print) -> None:
        if method not in AUTH_METHODS:
            raise ValueError(f"Unknown authentication method {method!r}")
        if method == "auto":
            method = "browser" if has_graphical_session() else "device"
        self._method = method
        self._notify = notify
        self._cache, self.cache_is_persistent = _build_token_cache(settings)
        self._app = msal.PublicClientApplication(
            settings.client_id,
            authority=settings.authority,
            token_cache=self._cache,
        )

    # -- public API -------------------------------------------------------

    def get_access_token(self, scopes: Sequence[str], *,
                         interactive: bool = True) -> str:
        """Return a valid access token for *scopes*.

        A cached token is used (and silently refreshed) when possible;
        otherwise the user is asked to sign in, unless *interactive* is
        false.

        Raises:
            AuthenticationError: if no token could be obtained.
        """
        result = self._acquire_silently(scopes)
        if result is None:
            if not interactive:
                raise AuthenticationError(
                    "Not signed in. Run: python -m counter_spam login")
            result = self._acquire_interactively(scopes)
        return self._extract_access_token(result)

    def token_provider(self, scopes: Sequence[str]) -> Callable[[], str]:
        """Return a zero-argument callable yielding fresh access tokens.

        Calling MSAL on every request is cheap (tokens are served from
        the cache) and guarantees that an expired token gets refreshed.
        """
        scopes = list(scopes)
        return lambda: self.get_access_token(scopes)

    def signed_in_username(self) -> str | None:
        """Return the username of the cached account, if any."""
        accounts = self._app.get_accounts()
        return accounts[0].get("username") if accounts else None

    def signed_in_name(self) -> str:
        """Return the display name of the cached account, if known.

        It comes from the ID token claims: no extra permission is needed.
        """
        accounts = self._app.get_accounts()
        if not accounts:
            return ""
        result = self._app.acquire_token_silent([MAIL_READ],
                                                account=accounts[0]) or {}
        claims = result.get("id_token_claims") or {}
        name = claims.get("name")
        return name if isinstance(name, str) else ""

    def logout(self) -> int:
        """Remove every cached account and return how many were removed."""
        accounts = self._app.get_accounts()
        for account in accounts:
            self._app.remove_account(account)
        return len(accounts)

    # -- internals --------------------------------------------------------

    def _acquire_silently(self, scopes: Iterable[str]) -> dict | None:
        """Try the token cache; return ``None`` if user action is needed."""
        accounts = self._app.get_accounts()
        if not accounts:
            return None
        if len(accounts) > 1:
            log.debug("Several cached accounts, using %s",
                      accounts[0].get("username"))
        result = self._app.acquire_token_silent(list(scopes),
                                                account=accounts[0])
        if result and "access_token" in result:
            return result
        # e.g. "interaction_required" for a scope not consented yet.
        if result:
            log.debug("Silent acquisition failed: %s", result.get("error"))
        return None

    def _acquire_interactively(self, scopes: Iterable[str]) -> dict:
        """Run the configured interactive sign-in flow."""
        if self._method == "browser":
            # MSAL implements the authorization code flow with PKCE and a
            # loopback redirect URI (http://localhost): the browser hands
            # the one-time authorization code back to this process only.
            self._notify("A browser window is opening on the Microsoft "
                         "sign-in page...")
            return self._app.acquire_token_interactive(
                list(scopes), prompt="select_account", timeout=300)
        return self._acquire_with_device_code(scopes)

    def _acquire_with_device_code(self, scopes: Iterable[str]) -> dict:
        """Run the OAuth 2.0 device authorization grant (RFC 8628)."""
        flow = self._app.initiate_device_flow(scopes=list(scopes))
        if "user_code" not in flow:
            raise AuthenticationError(
                "Unable to start the device code flow: "
                f"{flow.get('error_description') or flow.get('error')}")
        # The message contains the verification URL and the one-time code.
        self._notify(flow["message"])
        # Blocks until the user completes sign-in or the code expires.
        return self._app.acquire_token_by_device_flow(flow)

    @staticmethod
    def _extract_access_token(result: dict | None) -> str:
        """Return the access token from an MSAL result or raise."""
        if result and "access_token" in result:
            return result["access_token"]
        error = (result or {}).get("error_description") or \
            (result or {}).get("error") or "unknown error"
        raise AuthenticationError(f"Authentication failed: {error}")
