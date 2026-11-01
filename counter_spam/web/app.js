/*
 * Counter-Spam web interface.
 *
 * Security: every piece of spam-derived data is inserted with textContent
 * (never innerHTML), so a malicious subject or sender cannot inject HTML
 * or scripts.  The session token is kept in sessionStorage and sent in a
 * custom header that other sites cannot set.
 */
"use strict";

const TOKEN_HEADER = "X-Counter-Spam-Token";
const POLL_MS = 1000;
const SEND_POLL_MS = 400;

const KIND_LABELS = {
  "sending-server": "sending server",
  "sending-domain": "authenticated sending domain",
  "link-domain": "advertised domain",
  "link-hosting": "advertised website hosting",
  "declared": "contact declared by the sender",
};
const PHASE_LABELS = {
  idle: "Ready.",
  analysing: "Analyzing…",
  ready: "Analysis complete.",
  sending: "Sending…",
  done: "Sending complete.",
  error: "Error",
};

const token = (() => {
  const params = new URLSearchParams(window.location.search);
  let value = params.get("t") || "";
  try {
    if (value) {
      sessionStorage.setItem("counter-spam-token", value);
    } else {
      value = sessionStorage.getItem("counter-spam-token") || "";
    }
  } catch (error) {
    // Storage may be unavailable (private mode): keep the URL token.
  }
  if (params.get("t")) {
    // Remove the token from the address bar and the history.
    window.history.replaceState(null, "", "/");
  }
  return value;
})();

const selected = new Set();
const sent = new Set();
// Per group: its card, checkbox and status line, to update them in place.
const cards = new Map();
// Errors of the last action, shown in the page instead of a pop-up.
const actionErrors = { analyse: "", send: "" };
let renderedPlanVersion = -1;
let keepSelection = false;
let pollTimer = null;
let lastState = null;

// -- helpers ---------------------------------------------------------------

/** Create an element; strings become text nodes, never HTML. */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") {
      node.className = value;
    } else if (key === "text") {
      node.textContent = value;
    } else if (key.startsWith("on")) {
      node.addEventListener(key.slice(2), value);
    } else if (value !== false && value !== null && value !== undefined) {
      node.setAttribute(key, value === true ? "" : String(value));
    }
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) {
      node.append(child instanceof Node ? child : String(child));
    }
  }
  return node;
}

async function api(path, body) {
  const options = { headers: { [TOKEN_HEADER]: token } };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const label = button.textContent;
    button.textContent = "Copied ✓";
    setTimeout(() => { button.textContent = label; }, 1500);
  } catch (error) {
    window.prompt("Copy the text below:", text);
  }
}

function describeFinding(finding) {
  const label = KIND_LABELS[finding.kind] || finding.kind;
  const via = finding.via ? ` (website ${finding.via})` : "";
  return `${label}: ${finding.resource}${via}`;
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

// -- rendering -------------------------------------------------------------

function isBusy(state) {
  return Boolean(state)
    && (state.phase === "analysing" || state.phase === "sending");
}

function renderStatus(state) {
  document.getElementById("account").textContent =
    state.account ? `Signed in as ${state.account}` : "Not signed in";
  const status = document.getElementById("status");
  const progress = document.getElementById("progress");
  let text = PHASE_LABELS[state.phase] || state.phase;
  if (state.phase === "error") {
    text += `: ${state.error}`;
  }
  const { done, total, label } = state.progress;
  const analysing = state.phase === "analysing";
  if (analysing && total) {
    text += ` ${label} ${done}/${total}`;
  }
  if (actionErrors.analyse) {
    text = actionErrors.analyse;
  }
  status.textContent = text;
  status.classList.toggle("error",
    state.phase === "error" || Boolean(actionErrors.analyse));
  progress.hidden = !analysing;
  progress.max = total || 1;
  progress.value = done;
  const button = document.getElementById("analyse");
  button.disabled = isBusy(state);
  button.textContent = state.plan ? "Analyze again" : "Analyze";
  renderSendProgress(state);
  updateSendButton(state);
}

/** Progress of the sending, shown in the "Send" section. */
function renderSendProgress(state) {
  const box = document.getElementById("send-progress");
  const bar = document.getElementById("send-bar");
  const text = document.getElementById("send-status");
  const { done, total, label } = state.progress;
  text.classList.toggle("error", Boolean(actionErrors.send));
  if (actionErrors.send) {
    box.hidden = false;
    bar.hidden = true;
    text.textContent = actionErrors.send;
    return;
  }
  bar.hidden = false;
  box.hidden = state.phase !== "sending" && state.phase !== "done";
  if (box.hidden) {
    return;
  }
  if (state.phase === "done") {
    const ok = state.results.filter((result) => result.ok).length;
    bar.max = state.results.length || 1;
    bar.value = bar.max;
    text.textContent = `${ok} of ${plural(state.results.length,
      "report")} sent.`;
  } else if (!total) {
    // Before the first e-mail: Microsoft may ask for the Mail.Send consent.
    bar.removeAttribute("value");
    text.textContent = "Waiting for Microsoft to authorize sending… "
      + "Check your browser if a sign-in window opened.";
  } else {
    bar.max = total;
    bar.value = done;
    text.textContent = done < total
      ? `Sending report ${done + 1} of ${total} — ${label}`
      : `Finishing (${total} of ${total})…`;
  }
}

function setSelected(group, checked) {
  const card = cards.get(group.id);
  if (checked) {
    selected.add(group.id);
  } else {
    selected.delete(group.id);
  }
  if (card && card.checkbox) {
    card.checkbox.checked = checked;
    card.node.classList.toggle("selected", checked);
  }
}

function button(text, onclick, props = {}) {
  return el("button", { type: "button", text, onclick, ...props });
}

function groupCard(group) {
  const checkbox = group.sendsEmail
    ? el("input", {
      type: "checkbox",
      "aria-label": `Send the report to ${group.email}`,
      onchange: (event) => {
        setSelected(group, event.target.checked);
        updateSendButton(lastState);
      },
    })
    : null;

  const badges = el("div", { class: "badges" },
    el("span", { class: "badge", text: plural(group.count, "spam") }),
    group.parts > 1
      ? el("span", { class: "badge", text: `${group.parts} e-mails` })
      : null,
    formBadge(group),
    group.optional
      ? el("span", { class: "badge muted", text: "Optional" })
      : null,
    group.kinds.map((kind) =>
      el("span", { class: "badge kind", text: KIND_LABELS[kind] || kind })));

  const status = el("p", { class: "card-status", role: "status",
    "aria-live": "polite", hidden: true });

  // Only shown up front for providers that need their form; for the
  // others it appears once the form has been filled in instead.
  const mark = button("Mark as reported", () => markReported(group),
    { title: "Use it once the web form is submitted: these spams will "
      + "not be offered again for this provider.",
    hidden: group.sendsEmail && !lastState.autofill[group.id] });

  const actions = el("div", { class: "actions" });
  if (group.formUrl) {
    actions.append(button(
      group.sendsEmail ? "Fill in the web form instead"
        : "Fill in the form automatically",
      (event) => startAutofill(group, event.target, mark),
      { class: group.sendsEmail ? "" : "primary",
        title: "Opens the form in a new browser window and fills it in. "
          + "You review it, solve the CAPTCHA if any and submit it."
          + (group.sendsEmail ? " The e-mail report is then unticked." : ""),
      }));
  }
  if (group.formUrl || !group.sendsEmail) {
    actions.append(mark);
  }

  const tools = group.formUrl
    ? el("details", { class: "more" },
      el("summary", { text: "More options" }),
      el("div", { class: "actions" },
        button("Open the form", () => window.open(group.formUrl, "_blank",
          "noopener,noreferrer")),
        button("Copy the report",
          (event) => copy(group.preview, event.target)),
        button("Copy IPs / domains",
          (event) => copy(group.resources.join("\n"), event.target)),
        el("a", {
          class: "button",
          href: `/api/eml?group=${encodeURIComponent(group.id)}` +
            `&t=${encodeURIComponent(token)}`,
          download: "counter-spam-messages.zip",
          text: "Download the .eml files",
        })))
    : null;

  const messages = el("ol", { class: "messages" },
    group.messages.map((message) => el("li", {},
      el("strong", { text: message.subject }),
      el("span", { class: "meta", text: `${message.date} — ${message.sender}` }),
      el("span", {
        class: "meta",
        text: message.findings.map(describeFinding).join(" · "),
      }))));

  const node = el("article", { class: `group${group.optional
    ? " optional" : ""}` },
    el("header", {},
      el("label", { class: "group-title" }, checkbox,
        el("span", {},
          el("strong", { text: group.name }),
          el("span", { class: "email", text: group.email }))),
      badges),
    formHint(group),
    actions,
    status,
    tools,
    el("details", {},
      el("summary", { text: `Show the ${plural(group.count, "message")} and `
        + "the report" }),
      messages,
      el("pre", { class: "preview", text: group.preview })));
  cards.set(group.id, { node, checkbox, status, badges });
  return node;
}

function formBadge(group) {
  if (!group.sendsEmail) {
    return el("span", {
      class: "badge ko",
      text: group.formUrl ? "Web form only" : "No e-mail (address bounced)",
    });
  }
  return group.formUrl
    ? el("span", { class: "badge warn", text: "Web form preferred" })
    : null;
}

function formHint(group) {
  if (!group.sendsEmail) {
    return el("p", {
      class: "hint",
      text: `${group.formHint} `
        + (group.formUrl
          ? "Fill in the web form, then mark these spams as reported."
          : "No e-mail will be sent to this address."),
    });
  }
  return group.formUrl
    ? el("p", {
      class: "hint",
      text: "Its web form gets the report handled faster. "
        + (group.formHint || ""),
    })
    : null;
}

/** One block of cards: the e-mail reports, or the web forms. */
function groupList(title, help, groups, tools) {
  return el("section", { class: "group-list" },
    el("div", { class: "group-list-head" },
      el("h3", { text: `${title} (${groups.length})` }),
      tools),
    el("p", { class: "hint", text: help }),
    groups.map(groupCard));
}

function selectAll(checked) {
  for (const group of lastState.plan.groups) {
    if (group.sendsEmail && !sent.has(group.id)) {
      setSelected(group, checked);
    }
  }
  updateSendButton(lastState);
}

function renderSummary(plan) {
  const byEmail = plan.groups.filter((group) => group.sendsEmail);
  const byForm = plan.groups.length - byEmail.length;
  let text = `${plural(plan.count, "spam message")} analyzed: `
    + `${plural(byEmail.length, "report")} to send by e-mail`;
  if (byForm) {
    text += `, ${byForm} ${byForm === 1 ? "provider" : "providers"} `
      + "to report through a web form";
  }
  const notes = [];
  if (plan.alreadyReported) {
    notes.push(`${plural(plan.alreadyReported, "report")} already sent `
      + "before were skipped.");
  }
  if (plan.orphans.length) {
    notes.push(`No abuse contact found for ${plural(plan.orphans.length,
      "message")}.`);
  }
  if (plan.learned.length) {
    notes.push("Learned from their replies: "
      + plan.learned.map((item) => `${item.email} `
        + (item.status === "bounced" ? "bounces" : "only accepts its web form"))
        .join(", ") + ".");
  }
  const summary = document.getElementById("summary");
  summary.replaceChildren(el("p", { text: `${text}.` }));
  if (notes.length) {
    summary.append(el("ul", { class: "notes" },
      notes.map((note) => el("li", { text: note }))));
  }
}

function renderPlan(state) {
  const section = document.getElementById("plan");
  const plan = state.plan;
  section.hidden = !plan;
  document.getElementById("sending").hidden = !plan || !plan.count;
  if (!plan || state.planVersion === renderedPlanVersion) {
    return;
  }
  renderedPlanVersion = state.planVersion;
  // After "Mark as reported", the other cards keep the user's choices.
  const previous = keepSelection ? new Set(selected) : null;
  keepSelection = false;
  selected.clear();
  sent.clear();
  cards.clear();

  if (!plan.count) {
    document.getElementById("summary").textContent =
      "The Junk folder is empty: nothing to report.";
    document.getElementById("groups").replaceChildren();
    updateSendButton(state);
    return;
  }
  renderSummary(plan);
  const byEmail = plan.groups.filter((group) => group.sendsEmail);
  const byForm = plan.groups.filter((group) => !group.sendsEmail);
  const lists = [
    byEmail.length
      ? groupList("Reports sent by e-mail",
        "Ticked reports are sent when you click Send. Optional reports "
        + "go to anti-spam organisations rather than to the provider.",
        byEmail,
        el("div", { class: "select-tools" },
          button("Select all", () => selectAll(true), { class: "link" }),
          button("Select none", () => selectAll(false), { class: "link" })))
      : null,
    byForm.length
      ? groupList("Reports through a web form",
        "These providers do not accept e-mail reports: they are not part "
        + "of the sending.", byForm, null)
      : null,
  ].filter(Boolean);
  document.getElementById("groups").replaceChildren(...lists);
  plan.groups.forEach((group) => {
    if (group.sendsEmail) {
      setSelected(group, previous ? previous.has(group.id)
        : !group.optional);
    }
  });
  updateSendButton(state);
}

function renderResults(state) {
  const list = document.getElementById("results");
  list.replaceChildren(...state.results.map((result) => el("li", {
    class: result.ok ? "ok" : "ko",
    text: `${result.ok ? "✓" : "✗"} ${result.email}`
      + (result.parts > 1 ? ` (part ${result.part}/${result.parts})` : "")
      + (result.ok ? ": sent" : `: ${result.error}`),
  })));
  // A report sent once cannot be selected again: no duplicate e-mails.
  for (const result of state.results) {
    const card = cards.get(result.groupId);
    if (!result.ok || sent.has(result.groupId) || !card) {
      continue;
    }
    sent.add(result.groupId);
    selected.delete(result.groupId);
    card.checkbox.checked = false;
    card.checkbox.disabled = true;
    card.node.classList.remove("selected");
    card.node.classList.add("sent");
    card.badges.prepend(el("span", { class: "badge ok", text: "Sent" }));
  }
}

function updateSendButton(state) {
  const bar = document.getElementById("sendbar");
  const sendButton = document.getElementById("send");
  const info = document.getElementById("selection");
  const plan = state && state.plan;
  bar.hidden = !plan || !plan.count;
  if (bar.hidden) {
    return;
  }
  const available = plan.groups.filter((group) => group.sendsEmail
    && !sent.has(group.id)).length;
  if (state.phase === "sending") {
    sendButton.textContent = "Sending…";
  } else {
    sendButton.textContent = selected.size
      ? `Send ${plural(selected.size, "report")}`
      : "No report selected";
  }
  sendButton.disabled = isBusy(state) || selected.size === 0;
  if (!available && sent.size) {
    info.textContent = "All the e-mail reports are sent.";
  } else if (!available) {
    info.textContent = "No report to send by e-mail.";
  } else {
    info.textContent = `${selected.size} of ${plural(available,
      "e-mail report")} selected.`;
  }
}

function showCardStatus(groupId, text, kind) {
  const card = cards.get(groupId);
  if (card) {
    card.status.hidden = false;
    card.status.textContent = text;
    card.status.className = `card-status ${kind}`;
  }
}

function renderAutofill(state) {
  for (const [groupId, job] of Object.entries(state.autofill || {})) {
    showCardStatus(groupId, job.message, job.state);
  }
}

function autofillRunning(state) {
  return Object.values(state.autofill || {})
    .some((job) => job.state === "running");
}

function render(state) {
  lastState = state;
  renderPlan(state);
  renderResults(state);
  renderStatus(state);
  renderAutofill(state);
}

// -- polling and actions ---------------------------------------------------

async function refresh() {
  try {
    const state = await api("/api/state");
    render(state);
    clearTimeout(pollTimer);
    if (isBusy(state) || autofillRunning(state)) {
      pollTimer = setTimeout(refresh,
        state.phase === "sending" ? SEND_POLL_MS : POLL_MS);
    }
    return state;
  } catch (error) {
    const status = document.getElementById("status");
    status.textContent = `Interface disconnected: ${error.message}`;
    status.classList.add("error");
    return null;
  }
}

async function analyse() {
  const limit = Number(document.getElementById("limit").value) || 50;
  const links = document.getElementById("links").checked;
  actionErrors.analyse = "";
  actionErrors.send = "";
  try {
    await api("/api/analyse", { limit, links });
  } catch (error) {
    actionErrors.analyse = `Could not start the analysis: ${error.message}`;
  }
  refresh();
}

async function send() {
  const groups = lastState.plan.groups.filter((g) => selected.has(g.id));
  const total = groups.reduce((sum, g) => sum + g.parts, 0);
  const list = groups.map((g) => `• ${g.name} <${g.email}>: `
    + plural(g.count, "spam message")).join("\n");
  const remove = document.getElementById("delete").checked;
  const question = `Send ${plural(total, "e-mail")} from `
    + `${lastState.account}?\n\n${list}\n\n`
    + (remove ? "The reported spam will be moved to Deleted Items.\n" : "")
    + "A copy of every report is kept in Sent Items.";
  if (!window.confirm(question)) {
    return;
  }
  actionErrors.send = "";
  try {
    await api("/api/send", {
      groups: [...selected],
      note: document.getElementById("note").value,
      delete: remove,
    });
  } catch (error) {
    actionErrors.send = `Could not send: ${error.message}`;
  }
  document.getElementById("sending").scrollIntoView({ block: "nearest" });
  refresh();
}

async function startAutofill(group, target, mark) {
  target.disabled = true;
  try {
    await api("/api/autofill", { group: group.id });
    // The form replaces the e-mail: never report twice, and offer to
    // record it once submitted.
    if (group.sendsEmail && !sent.has(group.id)) {
      setSelected(group, false);
      updateSendButton(lastState);
    }
    mark.hidden = false;
  } catch (error) {
    showCardStatus(group.id, error.message, "error");
  } finally {
    setTimeout(() => { target.disabled = false; }, 3000);
  }
  refresh();
}

async function markReported(group) {
  const question = `Mark the ${plural(group.count, "spam message")} of `
    + `${group.name} as reported?\n\nDo it once the web form is `
    + "submitted: they will not be offered again for this provider.";
  if (!window.confirm(question)) {
    return;
  }
  try {
    await api("/api/mark", { groups: [group.id] });
    keepSelection = true;
  } catch (error) {
    showCardStatus(group.id, error.message, "error");
  }
  refresh();
}

async function quit() {
  if (isBusy(lastState) && !window.confirm("An operation is still "
      + "running. Quit Counter-Spam anyway?")) {
    return;
  }
  try {
    await api("/api/quit", {});
  } finally {
    document.body.replaceChildren(el("main", {},
      el("p", { class: "panel", text: "Counter-Spam has stopped. You can "
        + "close this tab." })));
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("analyse").addEventListener("click", analyse);
  document.getElementById("send").addEventListener("click", send);
  document.getElementById("quit").addEventListener("click", quit);
  const state = await refresh();
  if (state && state.phase === "idle") {
    analyse();
  }
});
