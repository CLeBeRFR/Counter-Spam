#!/usr/bin/env python3
"""Generate the README screenshots from a fictitious mailbox.

The real web interface is started with fake Outlook and RDAP back-ends
(made-up spams, reserved ``.example`` domains, no network access, nothing
sent) and captured with headless Firefox through Selenium.

Requirements (not needed to use Counter-Spam)::

    pip install selenium
    # Firefox + geckodriver (the Ubuntu Firefox snap ships both)

Usage::

    python docs/make_screenshots.py
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import threading
import time
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from counter_spam import autofill, cli  # noqa: E402
from counter_spam.campaign import CampaignPlanner, ReportLedger  # noqa: E402
from counter_spam.graph import MessageSummary  # noqa: E402
from counter_spam.rdap import AbuseLookup  # noqa: E402
from counter_spam.webui import CounterSpamApp, make_server  # noqa: E402

OUTPUT = ROOT / "docs" / "images"
ACCOUNT = "marie.dupont@example.com"
WIDTH, HEIGHT = 1200, 860

# -- fictitious data --------------------------------------------------------

NETWORKS = {
    "20.12.180.10": ("Microsoft Corporation", "abuse@microsoft.com"),
    "20.119.220.5": ("Microsoft Corporation", "abuse@microsoft.com"),
    "40.86.200.7": ("Microsoft Corporation", "abuse@microsoft.com"),
    "88.198.10.20": ("Hetzner Online GmbH", "abuse@hetzner.com"),
    "104.21.10.10": ("Cloudflare, Inc.", "abuse@cloudflare.com"),
    "185.62.10.4": ("Bulletproof Hosting Ltd", "abuse@bp-hosting.example"),
}
REGISTRARS = {
    "bonus-casino.example": ("NameCheap, Inc.", "abuse@namecheap.com"),
    "suivi-colis.example": ("Dynadot Inc", "abuse@dynadot.com"),
    "credit-facile.example": ("NameCheap, Inc.", "abuse@namecheap.com"),
    "gagnant-du-jour.example": ("Dynadot Inc", "abuse@dynadot.com"),
}
HOSTING = {
    "bonus-casino.example": "104.21.10.10",
    "suivi-colis.example": "104.21.10.10",
    "credit-facile.example": "185.62.10.4",
    "gagnant-du-jour.example": "104.21.10.10",
}
SPAMS = [
    ("Votre colis est bloqué au centre de tri 📦",
     "Service Livraison <noreply@x7k2.example>", "20.12.180.10",
     "https://track.suivi-colis.example/p/8XK2"),
    ("Bonus de 400 % sur votre premier dépôt 🎰",
     "L'équipe Casino <promo@q9z.example>", "20.119.220.5",
     "https://play.bonus-casino.example/?ref=88"),
    ("Votre dossier de financement est approuvé ✅",
     "Conseiller Crédit <contact@r4t.example>", "40.86.200.7",
     "https://www.credit-facile.example/dossier"),
    ("Dernière chance : 145 tours gratuits",
     "Casino Royal <vip@m1n.example>", "20.12.180.10",
     "https://play.bonus-casino.example/?ref=91"),
    ("Mise à jour concernant votre livraison",
     "Suivi Colis <info@k8w.example>", "88.198.10.20",
     "https://suivi-colis.example/maj"),
    ("Félicitations, vous avez gagné un smartphone !",
     "Jeu Concours <jeu@p2s.example>", "20.119.220.5",
     "https://gagnant-du-jour.example/reclamer"),
    ("Rachat de crédits à taux réduit",
     "Sophie de Crédit Facile <sophie@v5b.example>", "40.86.200.7",
     "https://credit-facile.example/simulation"),
    ("Confirmez votre adresse pour la livraison",
     "Point Relais <relais@h3j.example>", "20.12.180.10",
     "https://suivi-colis.example/confirmer"),
    ("Votre bonus VIP expire ce soir",
     "Club VIP <club@t6y.example>", "88.198.10.20",
     "https://vip.bonus-casino.example/club"),
    ("Recevez 2 500 € de bienvenue",
     "Bonus Express <go@w0e.example>", "20.119.220.5",
     "https://bonus-casino.example/bienvenue"),
]


def make_raw(index: int, subject: str, sender: str, ip: str,
             link: str) -> bytes:
    """Build a realistic raw spam as received by Outlook."""
    message = EmailMessage()
    message["Received-SPF"] = (f"None (protection.outlook.com: sender does "
                               f"not designate permitted sender hosts) "
                               f"client-ip={ip}; helo=mail.forged.example;")
    message["Authentication-Results"] = (
        f"spf=none (sender IP is {ip}) smtp.mailfrom=forged.example; "
        "dkim=none (message not signed) header.d=none;dmarc=none")
    message["From"] = sender
    message["To"] = ACCOUNT
    message["Subject"] = subject
    sent = datetime(2026, 10, 31, 18, 0, tzinfo=timezone.utc) \
        - timedelta(hours=7 * index)
    message["Date"] = format_datetime(sent)
    message.set_content(f"Bonjour,\n\nCliquez ici : {link}\n")
    message.add_alternative(f'<p>Bonjour,</p><p><a href="{link}">'
                            "Cliquez ici</a></p>", subtype="html")
    return bytes(message)


MAILBOX = {f"m{index}": make_raw(index, *spam)
           for index, spam in enumerate(SPAMS)}


class FakeRdap:
    def lookup(self, target: str) -> AbuseLookup:
        time.sleep(0.05)  # Lets the progress bar show up.
        if target in NETWORKS:
            name, email = NETWORKS[target]
            return AbuseLookup(target, target, name, (email,))
        for domain, (name, email) in REGISTRARS.items():
            if target == domain or target.endswith("." + domain):
                return AbuseLookup(target, domain, name, (email,))
        return AbuseLookup(target)


def fake_client(send_delay: float = 0.0) -> mock.Mock:
    client = mock.Mock()
    # A short delay per report makes the sending progress visible.
    client.send_mail.side_effect = lambda *args, **kwargs: \
        time.sleep(send_delay)
    client.list_junk_messages.side_effect = lambda limit: [
        MessageSummary(key, "", "", "") for key in list(MAILBOX)[:limit]]
    client.get_message_mime.side_effect = MAILBOX.__getitem__
    client.list_sent_conversations.return_value = {}
    client.list_replies.return_value = []
    return client


def make_app() -> CounterSpamApp:
    authenticator = mock.Mock()
    authenticator.signed_in_username.return_value = ACCOUNT
    authenticator.signed_in_name.return_value = "Marie Dupont"
    ledger = ReportLedger(None)
    return CounterSpamApp(
        authenticator, ledger,
        planner_factory=lambda **options: CampaignPlanner(
            FakeRdap(), resolve=lambda domain: [HOSTING.get(domain, "")]
            if domain in HOSTING else [], ledger=ledger, **options),
        client_factory=lambda scopes: fake_client(send_delay=1.0))


# -- browser ----------------------------------------------------------------

def make_driver(dark: bool):
    from selenium import webdriver
    from selenium.webdriver.firefox.service import Service

    options = webdriver.FirefoxOptions()
    options.add_argument("-headless")
    options.set_preference("ui.systemUsesDarkTheme", 1 if dark else 0)
    options.set_preference("layout.css.devPixelsPerPx", "1.5")
    snap = Path("/snap/firefox/current/usr/lib/firefox")
    service = None
    if (snap / "geckodriver").exists():
        options.binary_location = str(snap / "firefox")
        service = Service(executable_path=str(snap / "geckodriver"))
        # The snap cannot read profiles created in /tmp.
        tmp = Path.home() / "snap" / "firefox" / "common" / "tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        os.environ["TMPDIR"] = str(tmp)
        tempfile.tempdir = str(tmp)
    driver = webdriver.Firefox(options=options, service=service)
    driver.set_window_rect(width=WIDTH, height=HEIGHT)
    return driver


def wait_for(driver, script: str, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if driver.execute_script(script):
            return
        time.sleep(0.1)
    raise TimeoutError(script)


def capture_interface(dark: bool) -> None:
    app = make_app()
    server, url = make_server(app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    driver = make_driver(dark)
    suffix = "dark" if dark else "light"
    try:
        driver.get(url)
        wait_for(driver, "return document.getElementById('status')"
                         ".textContent.includes('complete')")
        time.sleep(0.5)
        driver.save_screenshot(str(OUTPUT / f"overview-{suffix}.png"))

        # Details of the first group: messages and report preview.
        driver.execute_script(
            "const d = document.querySelector('.group details');"
            "d.open = true; d.querySelector('.preview').scrollTop = 0;"
            "document.querySelector('.group').scrollIntoView();")
        time.sleep(0.4)
        driver.find_element("css selector", ".group") \
            .screenshot(str(OUTPUT / f"report-{suffix}.png"))

        # Fake sending (no network): one global confirmation, results.
        driver.execute_script("document.querySelector('.group details')"
                              ".open = false;")
        driver.find_element("id", "note").send_keys(
            "These messages keep coming every day.")
        driver.find_element("id", "send").click()
        driver.switch_to.alert.accept()
        section = driver.find_element("id", "sending")
        driver.execute_script("arguments[0].scrollIntoView()", section)
        wait_for(driver, "return document.getElementById('send-status')"
                         ".textContent.includes('report 3 of')")
        time.sleep(0.2)
        section.screenshot(str(OUTPUT / f"sending-{suffix}.png"))
        wait_for(driver, "return document.getElementById('status')"
                         ".textContent.includes('Sending complete')")
        time.sleep(0.4)
        section.screenshot(str(OUTPUT / f"send-{suffix}.png"))
    finally:
        driver.quit()
        server.shutdown()
        server.server_close()


DEMO_FORM = """<!doctype html><meta charset="utf-8">
<title>Report abuse - Example Hosting</title><style>
body { font: 15px/1.5 system-ui, sans-serif; background: #f6f7f9;
       margin: 0; color: #1d2330; }
header { background: #0f6b5c; color: #fff; padding: 14px 28px;
         font-weight: 600; }
form { max-width: 720px; margin: 24px auto; background: #fff;
       padding: 24px 28px; border-radius: 10px;
       box-shadow: 0 2px 10px rgba(0,0,0,.08); }
label { display: block; margin: 14px 0 4px; font-weight: 600; }
input, textarea, select { width: 100%; box-sizing: border-box;
       padding: 8px; font: inherit; border: 1px solid #c9ced6;
       border-radius: 6px; }
textarea { height: 150px; }
.captcha { margin-top: 18px; padding: 12px; border: 1px dashed #c9ced6;
           border-radius: 6px; color: #69707d; }
button { margin-top: 18px; padding: 10px 18px; background: #0f6b5c;
         color: #fff; border: 0; border-radius: 6px; font: inherit; }
</style><header>Example Hosting - Abuse report</header><form>
<label for=name>Your name</label><input id=name name=name>
<label for=mail>Your e-mail</label><input id=mail name=email type=email>
<label for=cat>Abuse type</label><select id=cat name=type>
<option>Choose…</option><option>Copyright</option><option>Phishing</option>
<option>Spam</option></select>
<label for=ip>IP address(es)</label><input id=ip name=ip>
<label for=url>URL(s)</label><input id=url name=url>
<label for=d>Description</label><textarea id=d name=description></textarea>
<label for=f>Evidence</label><input id=f name=evidence type=file multiple>
<div class=captcha>☐ I'm not a robot (CAPTCHA)</div>
<button type=submit>Submit report</button></form>"""


def capture_autofill() -> None:
    """Show the automatic filling on a demo abuse form."""
    page = Path.home() / "snap" / "firefox" / "common" / "demo-form.html"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(DEMO_FORM, encoding="utf-8")
    attachments = autofill.write_attachments(
        list(MAILBOX.values())[:3], autofill.upload_directory() / "demo")
    data = autofill.FormData(
        reporter_email=ACCOUNT, reporter_name="Marie Dupont",
        subject="Abuse report: 3 unsolicited e-mails involving your "
                "services",
        body=("Dear Example Hosting abuse team,\n\nI received the 3 "
              "unsolicited e-mails (spam / phishing) listed below. They "
              "involve resources under your responsibility:\n\n  - web "
              "site advertised in the message: 104.21.10.10 (serving "
              "suivi-colis[.]example) -- 3 message(s)\n..."),
        urls=["https://track.suivi-colis.example/p/8XK2"],
        domains=["suivi-colis.example"], ips=["104.21.10.10"],
        attachments=attachments)
    driver = make_driver(dark=False)
    try:
        driver.set_window_rect(width=WIDTH, height=1100)
        autofill.fill_form(driver, page.as_uri(), data, wait_seconds=10)
        time.sleep(0.5)
        driver.save_screenshot(str(OUTPUT / "autofill.png"))
    finally:
        driver.quit()
        page.unlink()


def capture_terminal() -> None:
    """Render a ``counter_spam analyze`` run as a terminal window."""
    buffer = io.StringIO()
    authenticator = mock.Mock()
    with mock.patch.object(cli, "OutlookAuthenticator",
                           return_value=authenticator), \
            mock.patch.object(cli, "GraphMailClient",
                              return_value=fake_client()), \
            mock.patch.object(cli, "RdapClient", FakeRdap), \
            mock.patch.object(cli, "load_settings"), \
            mock.patch.object(cli, "_ledger",
                              return_value=ReportLedger(None)), \
            mock.patch("counter_spam.campaign.resolve_addresses",
                       lambda domain: [HOSTING[domain]]
                       if domain in HOSTING else []), \
            contextlib.redirect_stdout(buffer), \
            contextlib.redirect_stderr(io.StringIO()):
        cli.main(["analyze", "-n", "10"])
    output = buffer.getvalue().strip()
    lines = "\n".join(
        f'<span class="b">{line}</span>' if line.startswith("* ")
        else f'<span class="d">{line}</span>' if "Preferred form" in line
        else line
        for line in output.replace("&", "&amp;").replace("<", "&lt;")
        .split("\n")[:24])
    html = f"""<!doctype html><meta charset="utf-8"><style>
body {{ margin: 0; background: transparent; font: 14px/1.45 "DejaVu Sans Mono",
       "Menlo", monospace; }}
.win {{ margin: 24px; border-radius: 12px; overflow: hidden;
        background: #161b26; color: #d7dbe5;
        box-shadow: 0 18px 50px rgba(0,0,0,.35); width: 900px; }}
.bar {{ padding: 10px 14px; background: #222938; display: flex; gap: 8px; }}
.dot {{ width: 12px; height: 12px; border-radius: 50%; }}
pre {{ margin: 0; padding: 18px 20px; white-space: pre-wrap; }}
.p {{ color: #7ee787; }} .b {{ color: #8fb4ff; font-weight: bold; }}
.d {{ color: #e3b341; }}
</style><div class="win" id="win"><div class="bar">
<span class="dot" style="background:#ff5f57"></span>
<span class="dot" style="background:#febc2e"></span>
<span class="dot" style="background:#28c840"></span></div>
<pre><span class="p">$</span> python -m counter_spam analyze -n 10
{lines}</pre></div>"""
    page = Path.home() / "snap" / "firefox" / "common" / "terminal.html"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(html, encoding="utf-8")
    driver = make_driver(dark=True)
    try:
        driver.get(page.as_uri())
        driver.find_element("id", "win") \
            .screenshot(str(OUTPUT / "terminal.png"))
    finally:
        driver.quit()
        page.unlink()


if __name__ == "__main__":
    OUTPUT.mkdir(parents=True, exist_ok=True)
    # No pause between the (fake) sends.
    with mock.patch("counter_spam.campaign.time"):
        capture_interface(dark=False)
        capture_interface(dark=True)
    capture_terminal()
    capture_autofill()
    for path in sorted(OUTPUT.glob("*.png")):
        print(path.relative_to(ROOT))
