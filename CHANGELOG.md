# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-01

A complete rewrite: Counter-Spam is now an Outlook-focused application with
secure sign-in, a grouped reporting strategy and a web interface.

### Added

- **Secure Outlook sign-in** with OAuth 2.0 / OpenID Connect (MSAL): browser
  sign-in with PKCE or device code, no password handled by the program,
  least-privilege permissions requested only when needed, tokens encrypted
  by the operating system (DPAPI, Keychain, libsecret).
- **Microsoft Graph** mailbox access, with the locale-independent Junk
  folder, throttling retries, and the access token only ever sent to Graph.
- **Grouped reporting strategy**: sending servers, SPF/DKIM-authenticated
  domains and advertised websites (registrar and web host) are traced;
  findings are grouped into **one report per abuse desk** with a summary
  table and the original messages attached, split when too large.
- **RDAP** abuse contact lookup (IPv4, IPv6, domains), keeping abuse
  contacts only and skipping brand-protection registrars.
- **Web interface** (`counter-spam gui`): review every report, untick
  recipients, add a personal note, send everything after one confirmation
  with a progress bar, light and dark themes.
- **Learning from replies**: automatic replies asking for a web form, and
  bounces, are detected; those providers are no longer e-mailed.
- **Automatic filling of abuse web forms** (optional `[autofill]` extra):
  fields are recognised and filled in, the messages attached; the user
  reviews, solves the CAPTCHA and submits.
- **Mark as reported** for providers handled through their web form.
- Report ledger: a spam is never reported twice to the same desk.
- Built-in knowledge of providers preferring web forms (Microsoft,
  Cloudflare, Google Cloud, Dynadot, PublicDomainRegistry, Worldstream).
- Complete command line: `login`, `logout`, `whoami`, `list`, `show`,
  `analyze`, `report`, `gui`, `configure`.
- Windows, macOS and Linux support; installable package with a
  `counter-spam` command.
- Test suite of 1,400+ tests (unit, integration, real browser, fuzzing),
  about 99 % coverage; PEP 8 compliant.

### Changed

- WHOIS (which ran a system binary, and could download one on Windows) is
  replaced by RDAP over HTTPS.
- The `From` header and unauthenticated domains (HELO...) are no longer used
  to choose recipients: they are trivially forged.
- Reported spam is moved to *Deleted Items* (recoverable) instead of being
  purged, and only on request.

### Removed

- IMAP/SMTP with passwords stored in `imap_credentials.json`: Microsoft has
  retired password authentication for Outlook, and storing passwords in
  clear text was unsafe.
- Generic IMAP providers: this version targets Outlook.com and
  Microsoft 365.

### Security

- Spam is hostile input: terminal escape sequences and bidirectional
  characters are stripped, HTML is never rendered nor fetched, `.eml` file
  names no longer come from the subject (path traversal), and several
  crashes of the standard e-mail parser on malformed messages are handled.
- The local web server is bound to `127.0.0.1`, protected by a per-session
  token, `Host` validation and a strict Content-Security-Policy.

## Before 2.0.0

The original IMAP/WHOIS script, never tagged (last commit `50134da`).

[2.0.0]: https://github.com/CLeBeRFR/Counter-Spam/compare/50134da...v2.0.0
