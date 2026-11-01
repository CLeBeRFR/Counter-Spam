"""Automatic filling of the abuse desks' web forms.

Many abuse desks only process reports made through their web form.  This
module opens the form in a browser window driven by Selenium and fills in
every field it recognises: reporter e-mail and name, URLs / domains, IP
addresses, date, description and the spam messages as attachments.

What it deliberately never does:

* submit the form: the user reviews the content and clicks the button;
* solve or bypass CAPTCHAs and anti-bot checks: the user does it, the
  filler simply waits for the form to appear;
* tick checkboxes: they are consents or terms the user must accept;
* overwrite a field that already has a value.

The decision logic (:func:`plan_fill`) is a pure function working on
field descriptions, so it is tested without any browser.  Selenium is an
optional dependency: ``pip install "counter-spam[autofill]"``.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence

log = logging.getLogger(__name__)

#: How long to wait for the form (anti-bot check, sign-in...), seconds.
FORM_WAIT_SECONDS = 600
#: Fields needed before a page is considered to be "the form".
_MIN_FORM_FIELDS = 2
_MAX_ATTACHMENTS = 10

# Field roles.
EMAIL, NAME, URLS, DOMAINS, IPS, DATE, SUBJECT, BODY, FILES, CATEGORY = (
    "email", "name", "urls", "domains", "ips", "date", "subject", "body",
    "files", "category")

_SKIP = re.compile(r"captcha|turnstile|password|search|coupon|promo|"
                   r"phone|tel\b|address line|street|city|zip|postal|"
                   r"country|company|organi[sz]ation|login|username",
                   re.IGNORECASE)
_OFFENDING = re.compile(r"abus|offend|spammer|report(?:ed)?\b|malicious|"
                        r"phish|infring|violat|suspect", re.IGNORECASE)
_PATTERNS = (
    (IPS, re.compile(r"\bip\b|ip ?address|ipv[46]|source ip", re.I)),
    (URLS, re.compile(r"\burls?\b|link|web ?site|web ?page|\bpage\b", re.I)),
    (DOMAINS, re.compile(r"domain|host ?name|\bfqdn\b", re.I)),
    (DATE, re.compile(r"\bdate\b|when did|occur", re.I)),
    (SUBJECT, re.compile(r"subject|title|summary|headline", re.I)),
    (BODY, re.compile(r"detail|descri|comment|message|evidence|explain|"
                      r"information|notes?\b|content|log|header|reason|"
                      r"complaint|tell us", re.I)),
    (EMAIL, re.compile(r"e-?mail", re.I)),
    (NAME, re.compile(r"\bname\b|full ?name|your name|first|last", re.I)),
)
_CATEGORY_LABEL = re.compile(r"type|category|kind|reason|issue|abuse|"
                             r"service|topic|subject|report", re.I)
_CATEGORY_CHOICES = (re.compile(r"\bspam\b", re.I),
                     re.compile(r"phish", re.I),
                     re.compile(r"\babuse\b", re.I),
                     re.compile(r"not sure|unknown|other", re.I))


@dataclass
class FormData:
    """Everything that can be typed into an abuse form."""

    reporter_email: str = ""
    reporter_name: str = ""
    subject: str = ""
    body: str = ""
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    attachments: list[Path] = field(default_factory=list)


@dataclass(frozen=True)
class FieldInfo:
    """Description of a form field, as collected in the page."""

    index: int
    tag: str                    # input, textarea, select
    type: str = "text"          # text, email, url, date, file, radio...
    text: str = ""              # label, name, id, placeholder, aria-label
    placeholder: str = ""
    multiple: bool = False
    accept: str = ""
    options: tuple[str, ...] = ()
    group: str = ""             # radio group name
    has_value: bool = False


@dataclass(frozen=True)
class Action:
    """Value to put in one field."""

    index: int
    role: str
    value: str = ""             # text value, option label, or file paths


# -- decision logic ---------------------------------------------------------

def field_role(info: FieldInfo) -> str | None:
    """Return the role of a field, or ``None`` to leave it alone."""
    kind = info.type.lower()
    text = f"{info.text} {info.placeholder}"
    if kind in ("hidden", "submit", "button", "reset", "image", "password",
                "checkbox") or _SKIP.search(text):
        return None
    if kind == "file":
        return FILES
    if info.tag == "select" or kind == "radio":
        return CATEGORY if _CATEGORY_LABEL.search(text) else None
    if kind == "email":
        return DOMAINS if _OFFENDING.search(text) else EMAIL
    if kind == "url":
        return URLS
    if kind == "date":
        return DATE
    for role, pattern in _PATTERNS:
        if pattern.search(text):
            if role == EMAIL and _OFFENDING.search(text):
                return None  # The spammer's address: unknown, leave it.
            return role
    if info.tag == "textarea":
        return BODY
    return None


def _format_date(moment: datetime, info: FieldInfo) -> str:
    hint = info.placeholder.lower()
    if info.type == "date" or "yyyy-mm-dd" in hint:
        return moment.strftime("%Y-%m-%d")
    if hint.startswith("dd"):
        return moment.strftime("%d/%m/%Y")
    return moment.strftime("%m/%d/%Y")


def _choose_option(options: Sequence[str]) -> str:
    for pattern in _CATEGORY_CHOICES:
        for option in options:
            if pattern.search(option):
                return option
    return ""


def _value_for(role: str, info: FieldInfo, data: FormData,
               body_used: bool) -> str:
    joined = "\n" if info.tag == "textarea" else ", "
    if role == EMAIL:
        return data.reporter_email
    if role == NAME:
        return data.reporter_name
    if role == URLS:
        values = data.urls or [f"https://{domain}/" for domain in
                               data.domains]
        return joined.join(values) if info.tag == "textarea" or \
            info.multiple else (values[0] if values else "")
    if role == DOMAINS:
        return joined.join(data.domains) if info.tag == "textarea" else \
            ", ".join(data.domains)
    if role == IPS:
        return joined.join(data.ips)
    if role == DATE:
        return _format_date(data.first_seen, info) if data.first_seen \
            else ""
    if role == SUBJECT:
        return data.subject
    if role == BODY:
        # The report goes in the first description field only.
        return "" if body_used else data.body
    if role == CATEGORY:
        return _choose_option(info.options)
    if role == FILES:
        paths = data.attachments if info.multiple else data.attachments[:1]
        return "\n".join(str(path) for path in paths[:_MAX_ATTACHMENTS])
    return ""


def _choose_radio(members: Sequence[FieldInfo]) -> FieldInfo | None:
    """Pick the radio button matching the best category, if any."""
    for pattern in _CATEGORY_CHOICES:
        for member in members:
            if pattern.search(member.text):
                return member
    return None


def plan_fill(fields: Sequence[FieldInfo], data: FormData) -> list[Action]:
    """Decide which value goes in which field (pure function)."""
    actions: list[Action] = []
    body_used = False
    radio_groups: dict[str, list[FieldInfo]] = {}
    for info in fields:
        if info.type == "radio":
            radio_groups.setdefault(info.group, []).append(info)
    radio_groups_done: set[str] = set()
    for info in fields:
        if info.type == "radio":
            if info.group in radio_groups_done:
                continue
            radio_groups_done.add(info.group)
            members = radio_groups[info.group]
            if any(member.has_value for member in members) or \
                    not any(field_role(member) for member in members):
                continue
            choice = _choose_radio(members)
            if choice:
                actions.append(Action(choice.index, CATEGORY, "check"))
            continue
        if info.has_value:
            continue
        role = field_role(info)
        if role is None:
            continue
        value = _value_for(role, info, data, body_used)
        if not value:
            continue
        if role == BODY:
            body_used = True
        actions.append(Action(info.index, role, value))
    return actions


# -- attachments ------------------------------------------------------------

def upload_directory() -> Path:
    """Directory readable by the browser for the files to upload.

    The Ubuntu Firefox snap cannot read hidden directories nor ``/tmp``:
    its own ``~/snap/firefox/common`` folder is used in that case.
    """
    if _snap_firefox():
        base = Path.home() / "snap" / "firefox" / "common"
    else:
        base = Path(tempfile.gettempdir())
    return base / "counter-spam-upload"


def write_attachments(messages: Sequence[bytes], directory: Path,
                      accept: str = "") -> list[Path]:
    """Write the messages as files the form will accept.

    ``.eml`` is used when the form accepts it (or does not say), ``.txt``
    otherwise.  Files are private to the user (0600) and the directory is
    emptied first so that no old spam is uploaded by mistake.
    """
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, mode=0o700)
    accept = accept.lower()
    extension = ".eml" if not accept or ".eml" in accept or \
        "message/" in accept or "*" in accept else ".txt"
    paths = []
    for number, raw in enumerate(messages[:_MAX_ATTACHMENTS], 1):
        path = directory / f"spam-{number:03d}{extension}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | \
            getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
            handle.write(raw)
        paths.append(path)
    return paths


def zip_attachments(paths: Sequence[Path], directory: Path) -> Path:
    """Bundle several messages for single-file upload fields."""
    archive = directory / "spam-messages.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in paths:
            bundle.write(path, path.name)
    return archive


# -- browser ----------------------------------------------------------------

class AutofillUnavailable(RuntimeError):
    """Raised when no automatable browser is available."""


_COLLECT_JS = r"""
const fields = [];
const nodes = [...document.querySelectorAll('input, textarea, select')];
nodes.forEach((e, index) => {
  const style = window.getComputedStyle(e);
  if (e.disabled || e.readOnly || style.display === 'none'
      || style.visibility === 'hidden') { return; }
  const labels = e.labels ? [...e.labels].map(l => l.innerText) : [];
  const by = (e.getAttribute('aria-labelledby') || '').split(/\s+/)
    .map(id => document.getElementById(id)).filter(Boolean)
    .map(n => n.innerText);
  const legend = e.closest('fieldset')?.querySelector('legend')?.innerText;
  const text = [...labels, ...by, legend, e.name, e.id,
                e.getAttribute('aria-label'), e.title]
    .filter(Boolean).join(' ').replace(/\s+/g, ' ').slice(0, 300);
  fields.push({
    index, tag: e.tagName.toLowerCase(), type: (e.type || 'text'),
    text, placeholder: e.placeholder || '', multiple: !!e.multiple,
    accept: e.accept || '', group: e.type === 'radio' ? e.name : '',
    options: e.tagName === 'SELECT'
      ? [...e.options].map(o => o.text.trim())
      : (e.type === 'radio' ? [text] : []),
    has_value: e.type === 'radio' ? e.checked
      : (e.tagName === 'SELECT' ? e.selectedIndex > 0
         : (e.type === 'file' ? e.files.length > 0 : !!e.value))
  });
});
return fields;
"""

_APPLY_JS = r"""
const [index, role, value] = arguments;
const e = document.querySelectorAll('input, textarea, select')[index];
if (!e) { return false; }
if (e.tagName === 'SELECT') {
  const option = [...e.options].find(o => o.text.trim() === value);
  if (!option) { return false; }
  e.value = option.value;
} else if (e.type === 'radio') {
  e.click();
  e.style.outline = '3px solid #2f9e44';
  return true;
} else {
  const proto = e.tagName === 'TEXTAREA'
    ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, value);
}
for (const type of ['input', 'change', 'blur']) {
  e.dispatchEvent(new Event(type, { bubbles: true }));
}
e.style.outline = '3px solid #2f9e44';
return true;
"""

_BANNER_JS = r"""
if (document.getElementById('counter-spam-banner')) { return; }
const b = document.createElement('div');
b.id = 'counter-spam-banner';
b.textContent = arguments[0];
Object.assign(b.style, {position: 'fixed', left: '16px', right: '16px',
  bottom: '16px', zIndex: 2147483647, padding: '12px 16px',
  background: '#1d2330', color: '#fff', borderRadius: '8px',
  font: '14px/1.4 system-ui, sans-serif',
  boxShadow: '0 6px 24px rgba(0,0,0,.3)'});
b.addEventListener('click', () => b.remove());
document.body.appendChild(b);
"""

BANNER = ("Filled in by Counter-Spam (fields outlined in green). Review "
          "them, complete what is missing, solve the CAPTCHA if any, then "
          "submit the form yourself. Click to hide this message.")


def _snap_firefox() -> Path | None:
    snap = Path("/snap/firefox/current/usr/lib/firefox")
    return snap if sys.platform.startswith("linux") and \
        (snap / "geckodriver").exists() else None


def open_browser():
    """Start a visible browser driven by Selenium (Firefox, Chrome, Edge).

    Selenium Manager locates (and if needed downloads) the right driver
    on Windows, macOS and Linux; the Ubuntu Firefox snap ships its own.
    """
    try:
        from selenium import webdriver
        from selenium.common.exceptions import WebDriverException
    except ImportError as exc:
        raise AutofillUnavailable(
            "Automatic filling needs Selenium: "
            'pip install "counter-spam[autofill]"') from exc

    errors = []
    snap = _snap_firefox()
    if snap:
        from selenium.webdriver.firefox.service import Service

        # The snap cannot read profiles created in /tmp.
        tmp = Path.home() / "snap" / "firefox" / "common" / "tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        os.environ["TMPDIR"] = str(tmp)
        tempfile.tempdir = str(tmp)
        options = webdriver.FirefoxOptions()
        options.binary_location = str(snap / "firefox")
        try:
            return webdriver.Firefox(
                options=options,
                service=Service(executable_path=str(snap / "geckodriver")))
        except WebDriverException as exc:
            errors.append(f"Firefox (snap): {exc.msg}")
    for name in ("Firefox", "Chrome", "Edge"):
        try:
            return getattr(webdriver, name)()
        except (WebDriverException, OSError) as exc:
            errors.append(f"{name}: {getattr(exc, 'msg', exc)}")
    raise AutofillUnavailable("No browser could be started: "
                              + "; ".join(errors))


def _collect(driver) -> list[FieldInfo]:
    return [FieldInfo(index=item["index"], tag=item["tag"],
                      type=item["type"], text=item["text"],
                      placeholder=item["placeholder"],
                      multiple=item["multiple"], accept=item["accept"],
                      options=tuple(item["options"]), group=item["group"],
                      has_value=item["has_value"])
            for item in driver.execute_script(_COLLECT_JS)]


def _frames(driver):
    """Yield once per document: the page, then each (nested) frame."""
    yield
    for position in range(len(driver.find_elements("tag name", "iframe"))):
        try:
            driver.switch_to.frame(position)
        except Exception:  # Frame vanished meanwhile.
            continue
        try:
            yield from _frames(driver)
        finally:
            driver.switch_to.parent_frame()


def _fill_current_document(driver, data: FormData,
                           fields: Sequence[FieldInfo]) -> int:
    filled = 0
    for action in plan_fill(fields, data):
        info = next(item for item in fields if item.index == action.index)
        try:
            if action.role == FILES:
                paths = action.value.split("\n")
                if not info.multiple and len(data.attachments) > 1:
                    paths = [str(zip_attachments(
                        data.attachments, data.attachments[0].parent))]
                element = driver.execute_script(
                    "return document.querySelectorAll("
                    "'input, textarea, select')[arguments[0]]", action.index)
                element.send_keys("\n".join(paths))
                filled += 1
            elif driver.execute_script(_APPLY_JS, action.index, action.role,
                                       action.value):
                filled += 1
        except Exception as exc:  # One stubborn field must not stop us.
            log.info("Could not fill field %s (%s): %s", action.index,
                     action.role, exc)
    return filled


def fill_form(driver, url: str, data: FormData,
              status: Callable[[str], None] = lambda message: None,
              wait_seconds: float = FORM_WAIT_SECONDS) -> int:
    """Open *url* and fill its form; return the number of fields filled.

    The function waits until a form shows up: the user may first have to
    pass an anti-bot check or sign in, in the same window.
    """
    driver.get(url)
    deadline = time.monotonic() + wait_seconds
    status("Waiting for the form (pass the security check or sign in "
           "if asked)…")
    while True:
        filled = found = 0
        for _ in _frames(driver):
            fields = _collect(driver)
            # A password field means a sign-in page, not the form: never
            # type anything there, wait for the user to sign in.
            if any(info.type == "password" for info in fields):
                continue
            useful = sum(1 for info in fields if field_role(info))
            found += useful
            if useful >= _MIN_FORM_FIELDS:
                filled += _fill_current_document(driver, data, fields)
        if found >= _MIN_FORM_FIELDS:
            break
        if time.monotonic() > deadline:
            raise TimeoutError("The form did not appear in time.")
        time.sleep(2)
    driver.switch_to.default_content()
    driver.execute_script(_BANNER_JS, BANNER)
    status(f"{filled} field(s) filled in: review the form and submit it "
           "yourself.")
    return filled
