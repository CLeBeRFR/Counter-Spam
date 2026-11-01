"""Tests for the automatic filling of abuse web forms.

The decision logic is tested on field descriptions; the browser part runs
headless Firefox against local pages imitating real abuse forms (skipped
when Selenium or Firefox is not available).
"""

import http.server
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from counter_spam import autofill
from counter_spam.autofill import (BODY, CATEGORY, DATE, DOMAINS, EMAIL,
                                   FILES, IPS, NAME, SUBJECT, URLS, Action,
                                   FieldInfo, FormData, field_role,
                                   plan_fill, write_attachments)

DATA = FormData(
    reporter_email="me@example.com", reporter_name="Marie Dupont",
    subject="Abuse report: 2 unsolicited e-mails",
    body="Dear abuse team, ...",
    urls=["https://evil.example/p", "https://evil.example/q"],
    domains=["evil.example"], ips=["20.12.180.10", "40.86.200.7"],
    first_seen=datetime(2026, 10, 31, 18, 0, tzinfo=timezone.utc),
    attachments=[Path("/tmp/spam-001.eml"), Path("/tmp/spam-002.eml")])


def text_field(index, text, **kwargs):
    return FieldInfo(index=index, tag=kwargs.pop("tag", "input"),
                     text=text, **kwargs)


class TestRoles:
    @pytest.mark.parametrize("info, role", [
        (text_field(0, "Email address *", type="email"), EMAIL),
        (text_field(0, "Your e-mail"), EMAIL),
        (text_field(0, "Full name"), NAME),
        (text_field(0, "URL of the abusive content"), URLS),
        (text_field(0, "x", type="url"), URLS),
        (text_field(0, "Domain name"), DOMAINS),
        (text_field(0, "Source IP address"), IPS),
        (text_field(0, "Abuse date", placeholder="MM/DD/YYYY"), DATE),
        (text_field(0, "Subject"), SUBJECT),
        (text_field(0, "Abuse details *", tag="textarea"), BODY),
        (text_field(0, "", tag="textarea"), BODY),
        (text_field(0, "Logs", type="file"), FILES),
        (text_field(0, "Abuse type", tag="select"), CATEGORY),
    ])
    def test_recognised_fields(self, info, role):
        assert field_role(info) == role

    @pytest.mark.parametrize("info", [
        text_field(0, "I agree to the terms", type="checkbox"),
        text_field(0, "Password", type="password"),
        text_field(0, "g-recaptcha-response", tag="textarea"),
        text_field(0, "cf-turnstile-response"),
        text_field(0, "Search"),
        text_field(0, "Phone number"),
        text_field(0, "Company"),
        text_field(0, "token", type="hidden"),
        text_field(0, "Send", type="submit"),
        # The spammer's address is unknown: never put ours there.
        text_field(0, "Email address of the abuser"),
        text_field(0, "Favourite colour", tag="select"),
    ])
    def test_ignored_fields(self, info):
        assert field_role(info) is None


class TestPlan:
    def test_google_cloud_like_form(self):
        fields = [
            text_field(0, "This help content & information feedback-choice",
                       type="radio", group="feedback-choice"),
            text_field(1, "Name fullname_prefill"),
            text_field(2, "Email address * email_prefill_req"),
            text_field(3, "Not Sure Google_Cloud_Platform_Service",
                       type="radio", group="svc"),
            text_field(4, "Compute Engine Google_Cloud_Platform_Service",
                       type="radio", group="svc"),
            text_field(5, "Abuse date abuse_date", placeholder="MM/DD/YYYY"),
            text_field(6, "Abuse details * abuse_details", tag="textarea"),
            text_field(7, "Additional logs Abuse_logs", type="file"),
            text_field(8, "Google can ask for feedback", type="checkbox"),
            text_field(9, "g-recaptcha-response", tag="textarea"),
        ]
        assert plan_fill(fields, DATA) == [
            Action(1, NAME, "Marie Dupont"),
            Action(2, EMAIL, "me@example.com"),
            Action(3, CATEGORY, "check"),
            Action(5, DATE, "10/31/2026"),
            Action(6, BODY, "Dear abuse team, ..."),
            Action(7, FILES, "/tmp/spam-001.eml"),
        ]

    def test_report_goes_in_first_description_only(self):
        fields = [text_field(0, "Description", tag="textarea"),
                  text_field(1, "Comments", tag="textarea")]
        assert [a.index for a in plan_fill(fields, DATA)] == [0]

    def test_existing_values_are_kept(self):
        fields = [text_field(0, "Email", has_value=True),
                  text_field(1, "Name")]
        assert [a.index for a in plan_fill(fields, DATA)] == [1]

    def test_radio_priority_spam_then_phishing(self):
        fields = [text_field(0, "Other abuse_type", type="radio", group="t"),
                  text_field(1, "Phishing abuse_type", type="radio",
                             group="t"),
                  text_field(2, "Spam abuse_type", type="radio", group="t")]
        assert plan_fill(fields, DATA) == [Action(2, CATEGORY, "check")]

    def test_radio_group_already_answered(self):
        fields = [text_field(0, "Spam type", type="radio", group="t",
                             has_value=True),
                  text_field(1, "Other type", type="radio", group="t")]
        assert plan_fill(fields, DATA) == []

    def test_select_option(self):
        info = text_field(0, "Category", tag="select",
                          options=("Choose…", "Copyright", "Phishing",
                                   "Spam"))
        assert plan_fill([info], DATA) == [Action(0, CATEGORY, "Spam")]

    def test_select_without_matching_option(self):
        info = text_field(0, "Category", tag="select",
                          options=("Choose…", "Copyright"))
        assert plan_fill([info], DATA) == []

    def test_multiple_values(self):
        fields = [text_field(0, "IP addresses", tag="textarea"),
                  text_field(1, "URLs", multiple=True),
                  text_field(2, "Website URL")]
        actions = plan_fill(fields, DATA)
        assert actions[0].value == "20.12.180.10\n40.86.200.7"
        assert actions[1].value == ("https://evil.example/p, "
                                    "https://evil.example/q")
        assert actions[2].value == "https://evil.example/p"

    def test_urls_derived_from_domains(self):
        data = FormData(domains=["evil.example"])
        assert plan_fill([text_field(0, "URL")], data) == [
            Action(0, URLS, "https://evil.example/")]

    def test_multiple_file_input_gets_all_messages(self):
        info = text_field(0, "Evidence", type="file", multiple=True)
        assert plan_fill([info], DATA)[0].value == \
            "/tmp/spam-001.eml\n/tmp/spam-002.eml"

    @pytest.mark.parametrize("placeholder, kind, expected", [
        ("MM/DD/YYYY", "text", "10/31/2026"),
        ("DD/MM/YYYY", "text", "31/10/2026"),
        ("YYYY-MM-DD", "text", "2026-10-31"),
        ("", "date", "2026-10-31"),
    ])
    def test_date_formats(self, placeholder, kind, expected):
        info = text_field(0, "Date", type=kind, placeholder=placeholder)
        assert plan_fill([info], DATA)[0].value == expected

    def test_missing_data_leaves_fields_empty(self):
        fields = [text_field(0, "Name"), text_field(1, "Date"),
                  text_field(2, "IP")]
        assert plan_fill(fields, FormData()) == []


class TestAttachments:
    def test_files_are_private_and_directory_is_reset(self, tmp_path):
        directory = tmp_path / "upload"
        directory.mkdir()
        (directory / "old.eml").write_text("old spam")
        paths = write_attachments([b"one", b"two"], directory)
        assert [path.name for path in paths] == ["spam-001.eml",
                                                 "spam-002.eml"]
        assert not (directory / "old.eml").exists()
        assert paths[0].read_bytes() == b"one"

    def test_text_extension_when_eml_not_accepted(self, tmp_path):
        paths = write_attachments([b"x"], tmp_path / "u", accept=".txt,.pdf")
        assert paths[0].suffix == ".txt"

    def test_attachment_count_is_capped(self, tmp_path):
        paths = write_attachments([b"x"] * 25, tmp_path / "u")
        assert len(paths) == 10

    def test_zip_bundle(self, tmp_path):
        import zipfile

        paths = write_attachments([b"a", b"b"], tmp_path / "u")
        archive = autofill.zip_attachments(paths, tmp_path / "u")
        assert zipfile.ZipFile(archive).namelist() == ["spam-001.eml",
                                                       "spam-002.eml"]


def test_missing_selenium_is_reported(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_selenium(name, *args, **kwargs):
        if name.startswith("selenium"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_selenium)
    with pytest.raises(autofill.AutofillUnavailable, match="autofill"):
        autofill.open_browser()


# -- real browser against local pages ----------------------------------------

# Selenium's HTTP client to the browser driver leaves sockets to the garbage
# collector: harmless, but reported as warnings when they are errors.
browser_warnings = pytest.mark.filterwarnings(
    "ignore::ResourceWarning",
    "ignore::pytest.PytestUnraisableExceptionWarning")

GOOGLE_LIKE = """<!doctype html><title>Report abuse</title><form>
<label for=n>Name</label><input id=n name=fullname_prefill>
<label for=e>Email address *</label><input id=e name=email_prefill_req>
<fieldset><legend>Which service?</legend>
<label><input type=radio name=Service value=other>Other</label>
<label><input type=radio name=Service value=spam>Spam</label></fieldset>
<label for=d>Abuse date</label><input id=d name=abuse_date
 placeholder=MM/DD/YYYY>
<label for=t>Abuse details *</label><textarea id=t name=details></textarea>
<label for=f>Logs</label><input id=f type=file name=logs multiple>
<label><input type=checkbox id=terms> I accept the terms</label>
<textarea name=g-recaptcha-response style="display:none"></textarea>
<button id=submit type=submit>Send</button></form>
<script>document.getElementById('submit').onclick = () => {
  document.title = 'SUBMITTED'; return false; };</script>"""

IFRAME_HOST = """<!doctype html><title>Abuse</title>
<input name=search placeholder=Search>
<iframe src="/inner.html" width=600 height=600></iframe>"""
INNER = """<!doctype html><form>
<label>Your email<input type=email name=email></label>
<label>IP address<input name=ip></label>
<label>Category<select name=category><option>Choose</option>
<option>Copyright</option><option>Spam</option></select></label>
<label>Description<textarea name=description></textarea></label></form>"""
# An anti-bot check that shows the form after a few seconds.
CHALLENGE = """<!doctype html><title>Just a moment...</title>
<div id=root>Checking your browser…</div>
<script>setTimeout(() => { document.getElementById('root').innerHTML =
  '<label>Email<input name=email></label>' +
  '<label>Message<textarea name=message></textarea></label>';
  document.title = 'Abuse form'; }, 2500);</script>"""
LOGIN = """<!doctype html><title>Sign in</title>
<label>Email<input name=email></label>
<label>Password<input type=password name=password></label>
<label>Comment<textarea name=comment></textarea></label>"""

PAGES = {"/google.html": GOOGLE_LIKE, "/host.html": IFRAME_HOST,
         "/inner.html": INNER, "/challenge.html": CHALLENGE,
         "/login.html": LOGIN}


class _Pages(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # Name imposed by the stdlib.
        body = PAGES.get(self.path, "").encode()
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def site():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Pages)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def browser():
    webdriver = pytest.importorskip("selenium.webdriver")
    snap = autofill._snap_firefox()
    options = webdriver.FirefoxOptions()
    options.add_argument("-headless")
    try:
        if snap:
            from selenium.webdriver.firefox.service import Service
            import os
            import tempfile

            tmp = Path.home() / "snap" / "firefox" / "common" / "tmp"
            tmp.mkdir(parents=True, exist_ok=True)
            os.environ["TMPDIR"] = str(tmp)
            tempfile.tempdir = str(tmp)
            options.binary_location = str(snap / "firefox")
            driver = webdriver.Firefox(options=options, service=Service(
                executable_path=str(snap / "geckodriver")))
        else:
            driver = webdriver.Firefox(options=options)
    except Exception as exc:  # No usable Firefox on this machine.
        pytest.skip(f"Firefox unavailable: {exc}")
    yield driver
    driver.quit()


def values(driver, *selectors):
    return [driver.execute_script(
        f"return document.querySelector('{selector}').value")
        for selector in selectors]


@pytest.fixture
def data_with_files():
    directory = autofill.upload_directory() / "tests"
    paths = write_attachments([b"Subject: one\r\n\r\n",
                               b"Subject: two\r\n\r\n"], directory)
    return FormData(**{**DATA.__dict__, "attachments": paths})


@browser_warnings
def test_fills_google_like_form_without_submitting(browser, site,
                                                   data_with_files):
    filled = autofill.fill_form(browser, f"{site}/google.html",
                                data_with_files, wait_seconds=10)
    assert filled == 6
    assert values(browser, "#n", "#e", "#d", "#t") == [
        "Marie Dupont", "me@example.com", "10/31/2026",
        "Dear abuse team, ..."]
    assert browser.execute_script(
        "return document.querySelector('input[value=spam]').checked")
    assert browser.execute_script(
        "return document.getElementById('f').files.length") == 2
    # Never submitted, terms never accepted, CAPTCHA untouched.
    assert browser.title == "Report abuse"
    assert not browser.execute_script(
        "return document.getElementById('terms').checked")
    assert browser.execute_script(
        "return document.querySelector('[name=g-recaptcha-response]')"
        ".value") == ""
    assert browser.execute_script(
        "return !!document.getElementById('counter-spam-banner')")


@browser_warnings
def test_fills_form_inside_iframe(browser, site):
    assert autofill.fill_form(browser, f"{site}/host.html", DATA,
                              wait_seconds=10) == 4
    browser.switch_to.frame(0)
    assert values(browser, "[name=email]", "[name=ip]", "[name=category]",
                  "[name=description]") == [
        "me@example.com", "20.12.180.10, 40.86.200.7", "Spam",
        "Dear abuse team, ..."]
    browser.switch_to.default_content()
    assert values(browser, "[name=search]") == [""]


@browser_warnings
def test_waits_for_anti_bot_check(browser, site):
    assert autofill.fill_form(browser, f"{site}/challenge.html", DATA,
                              wait_seconds=15) == 2
    assert values(browser, "[name=email]") == ["me@example.com"]


@browser_warnings
def test_never_types_into_a_sign_in_page(browser, site):
    with pytest.raises(TimeoutError):
        autofill.fill_form(browser, f"{site}/login.html", DATA,
                           wait_seconds=3)
    assert values(browser, "[name=email]", "[name=comment]") == ["", ""]


@browser_warnings
def test_user_input_is_preserved(browser, site):
    browser.get(f"{site}/google.html")
    browser.execute_script("document.getElementById('e').value = "
                           "'typed@by.user'")
    autofill._fill_current_document(browser, DATA,
                                    autofill._collect(browser))
    assert values(browser, "#e") == ["typed@by.user"]


@browser_warnings
def test_status_messages(browser, site):
    messages = []
    autofill.fill_form(browser, f"{site}/google.html", DATA,
                       status=messages.append, wait_seconds=10)
    assert messages[0].startswith("Waiting for the form")
    assert "review the form and submit it yourself" in messages[-1]
