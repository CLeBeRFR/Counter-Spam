"""Static security checks of the web interface files.

The page displays attacker-controlled text: these checks make sure the
front-end never uses an HTML-interpreting sink and never relies on inline
code, which the Content-Security-Policy would block anyway.
"""

import re
from importlib import resources

import pytest


def read(name: str) -> str:
    return resources.files("counter_spam").joinpath("web", name) \
        .read_text(encoding="utf-8")


def code_of(name: str) -> str:
    """Return a script without its comments (which may name sinks)."""
    script = re.sub(r"/\*.*?\*/", "", read(name), flags=re.DOTALL)
    return re.sub(r"^\s*//.*$", "", script, flags=re.MULTILINE)


@pytest.mark.parametrize("sink", [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "eval(", "new Function", "setTimeout(\"", "setInterval(\""])
def test_no_dangerous_dom_sinks(sink):
    assert sink not in code_of("app.js")


def test_new_windows_cannot_reach_back():
    calls = re.findall(r"window\.open\([^;]*;", read("app.js"), re.DOTALL)
    assert calls and all("noopener" in call for call in calls)


def test_html_has_no_inline_code():
    html = read("index.html")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE)
    assert "style=" not in html
    assert "javascript:" not in html.lower()


def test_no_remote_resources():
    for name in ("index.html", "app.js", "style.css"):
        content = read(name)
        assert not re.search(r"(src|href)=[\"']https?://", content)
        assert "@import" not in content
        assert "url(" not in content


def test_token_is_removed_from_address_bar():
    assert 'history.replaceState(null, "", "/")' in read("app.js")


def test_sending_requires_explicit_confirmation():
    script = read("app.js")
    send = script[script.index("async function send()"):]
    send = send[:send.index("\n}\n")]
    assert "window.confirm(" in send
    assert send.index("window.confirm(") < send.index('api("/api/send"')


def test_icon_is_static_svg():
    icon = read("icon.svg")
    assert icon.startswith("<svg")
    assert "<script" not in icon and "href=" not in icon


def test_interface_is_in_english():
    html = read("index.html")
    assert '<html lang="en">' in html
    for text in ("Analyze the Junk folder", "Review the reports", "Send"):
        assert text in html
    assert not re.search(r"[àâéèêëîïôùûüç«»]", html + code_of("app.js"))


def test_sending_progress_bar_is_accessible():
    html = read("index.html")
    assert 'id="send-progress"' in html
    assert re.search(r'<progress id="send-bar"[^>]*aria-labelledby='
                     r'"send-status"', html)
    assert re.search(r'id="send-status" role="status" aria-live="polite"',
                     html)
    script = code_of("app.js")
    assert "function renderSendProgress(state)" in script
    assert "Sending report ${done + 1} of ${total}" in script


def test_autofill_button_and_live_status():
    script = code_of("app.js")
    assert '"Fill in the form automatically"' in script
    assert 'api("/api/autofill", { group: group.id })' in script
    # The filler never submits: the UI says so to the user.
    assert "You review it, solve the CAPTCHA if any and submit it." in script
    assert "autofillRunning(state)" in script


def test_english_plural_and_empty_folder():
    script = code_of("app.js")
    assert '${count === 1 ? "" : "s"}' in script
    assert "The Junk folder is empty: nothing to report." in script


def test_send_button_is_always_in_reach():
    html = read("index.html")
    assert re.search(r'<div class="sendbar" id="sendbar" hidden>\s*'
                     r'<p id="selection" aria-live="polite"></p>\s*'
                     r'<button type="button" class="primary" id="send">',
                     html)
    css = read("style.css")
    sendbar = css[css.index(".sendbar {"):]
    assert "position: sticky" in sendbar[:sendbar.index("}")]
    # Author display rules must not reveal elements marked hidden.
    assert "[hidden] { display: none !important; }" in css


def test_reports_are_split_by_channel():
    script = code_of("app.js")
    assert '"Reports sent by e-mail"' in script
    assert '"Reports through a web form"' in script
    assert '"More options"' in script
    assert 'button("Select all", () => selectAll(true)' in script


def test_errors_are_shown_in_the_page():
    assert "window.alert(" not in code_of("app.js")


def test_sent_reports_cannot_be_sent_twice():
    script = code_of("app.js")
    results = script[script.index("function renderResults(state)"):]
    results = results[:results.index("\n}\n")]
    assert "sent.add(result.groupId)" in results
    assert "selected.delete(result.groupId)" in results
    assert "card.checkbox.disabled = true" in results


def test_filling_the_form_instead_unticks_the_email():
    script = code_of("app.js")
    autofill = script[script.index("async function startAutofill("):]
    autofill = autofill[:autofill.index("\n}\n")]
    assert "setSelected(group, false)" in autofill
    assert "mark.hidden = false" in autofill
