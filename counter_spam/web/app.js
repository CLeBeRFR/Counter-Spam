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
const autofillStatus = new Map();
let renderedPlanVersion = -1;
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
  status.textContent = text;
  status.classList.toggle("error", state.phase === "error");
  progress.hidden = !analysing;
  progress.max = total || 1;
  progress.value = done;
  document.getElementById("analyse").disabled = analysing
    || state.phase === "sending";
  renderSendProgress(state);
  updateSendButton(state);
}

/** Progress of the sending, shown right under the "Send" button. */
function renderSendProgress(state) {
  const box = document.getElementById("send-progress");
  const bar = document.getElementById("send-bar");
  const text = document.getElementById("send-status");
  const { done, total, label } = state.progress;
  box.hidden = state.phase !== "sending" && state.phase !== "done";
  if (box.hidden) {
    return;
  }
  if (state.phase === "done") {
    const sent = state.results.filter((result) => result.ok).length;
    bar.max = state.results.length || 1;
    bar.value = bar.max;
    text.textContent = `${sent} of ${plural(state.results.length,
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

function groupCard(group) {
  const checkbox = group.sendsEmail
    ? el("input", {
      type: "checkbox",
      checked: selected.has(group.id),
      "aria-label": `Send the report to ${group.email}`,
      onchange: (event) => {
        if (event.target.checked) {
          selected.add(group.id);
        } else {
          selected.delete(group.id);
        }
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

  const actions = el("div", { class: "actions" });
  if (group.formUrl) {
    actions.append(
      el("button", {
        type: "button",
        class: "primary",
        text: "Fill in the form automatically",
        title: "Opens the form in a new browser window and fills it in. "
          + "You review it, solve the CAPTCHA if any and submit it.",
        onclick: (event) => startAutofill(group, event.target),
      }),
      el("button", {
        type: "button",
        text: "Open the form",
        onclick: () => window.open(group.formUrl, "_blank",
          "noopener,noreferrer"),
      }),
      el("button", {
        type: "button",
        text: "Copy the report",
        onclick: (event) => copy(group.preview, event.target),
      }),
      el("button", {
        type: "button",
        text: "Copy IPs / domains",
        onclick: (event) => copy(group.resources.join("\n"), event.target),
      }),
      el("a", {
        class: "button",
        href: `/api/eml?group=${encodeURIComponent(group.id)}` +
          `&t=${encodeURIComponent(token)}`,
        download: "counter-spam-messages.zip",
        text: "Download the .eml files",
      }));
  }
  if (!group.sendsEmail) {
    actions.append(el("button", {
      type: "button",
      text: "Mark as reported",
      title: "Use it once the web form is submitted: these spams will "
        + "not be offered again for this provider.",
      onclick: () => markReported(group),
    }));
  }

  const messages = el("ol", { class: "messages" },
    group.messages.map((message) => el("li", {},
      el("strong", { text: message.subject }),
      el("span", { class: "meta", text: `${message.date} — ${message.sender}` }),
      el("span", {
        class: "meta",
        text: message.findings.map(describeFinding).join(" · "),
      }))));

  const status = el("p", { class: "autofill-status", role: "status",
    "aria-live": "polite", hidden: true });
  autofillStatus.set(group.id, status);

  return el("article", { class: `group${group.optional ? " optional" : ""}` },
    el("header", {},
      el("label", { class: "group-title" }, checkbox,
        el("span", {},
          el("strong", { text: group.name }),
          el("span", { class: "email", text: group.email }))),
      badges),
    formHint(group),
    actions,
    status,
    el("details", {},
      el("summary", { text: `Show the ${plural(group.count, "message")} and `
        + "the report" }),
      messages,
      el("pre", { class: "preview", text: group.preview })));
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
          ? "No e-mail will be sent: fill in the web form, then mark "
            + "these spams as reported."
          : "No e-mail will be sent to this address."),
    });
  }
  return group.formUrl
    ? el("p", {
      class: "hint",
      text: "This provider prefers its web form: the report is still "
        + "e-mailed when the box is ticked, but filling in the form gets "
        + "it handled faster. " + (group.formHint || ""),
    })
    : null;
}

function renderPlan(state) {
  const section = document.getElementById("plan");
  const plan = state.plan;
  section.hidden = !plan;
  document.getElementById("sending").hidden = !plan;
  if (!plan || state.planVersion === renderedPlanVersion) {
    return;
  }
  renderedPlanVersion = state.planVersion;
  selected.clear();
  autofillStatus.clear();
  plan.groups.forEach((group) => {
    if (group.sendsEmail && !group.optional) {
      selected.add(group.id);
    }
  });

  if (!plan.count) {
    document.getElementById("summary").textContent =
      "The Junk folder is empty: nothing to report.";
    document.getElementById("groups").replaceChildren();
    updateSendButton(state);
    return;
  }
  const emailGroups = plan.groups.filter((group) => !group.optional);
  const forms = plan.groups.filter((group) => group.formUrl).length;
  let summary = `${plural(plan.count, "spam message")} analyzed → `
    + `${plural(emailGroups.length, "report")} grouped by provider`;
  if (forms) {
    summary += `, ${forms} of which with a preferred web form`;
  }
  summary += ".";
  if (plan.alreadyReported) {
    summary += ` ${plural(plan.alreadyReported, "report")} already sent `
      + "before were skipped.";
  }
  if (plan.orphans.length) {
    summary += ` No abuse contact found for ${plural(plan.orphans.length,
      "message")}.`;
  }
  if (plan.learned.length) {
    summary += " Learned from their replies: "
      + plan.learned.map((item) => `${item.email} `
        + (item.status === "bounced" ? "bounces" : "only accepts its web form"))
        .join(", ") + ".";
  }
  document.getElementById("summary").textContent = summary;
  document.getElementById("groups").replaceChildren(
    ...plan.groups.map(groupCard));
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
}

function updateSendButton(state) {
  const button = document.getElementById("send");
  const busy = state && (state.phase === "analysing"
    || state.phase === "sending");
  button.textContent = selected.size
    ? `Send ${plural(selected.size, "report")}`
    : "No report selected";
  button.disabled = busy || selected.size === 0;
}

function renderAutofill(state) {
  for (const [groupId, status] of autofillStatus) {
    const job = state.autofill[groupId];
    status.hidden = !job;
    if (job) {
      status.textContent = job.message;
      status.className = `autofill-status ${job.state}`;
    }
  }
}

function autofillRunning(state) {
  return Object.values(state.autofill || {})
    .some((job) => job.state === "running");
}

function render(state) {
  lastState = state;
  renderStatus(state);
  renderPlan(state);
  renderResults(state);
  renderAutofill(state);
}

// -- polling and actions ---------------------------------------------------

async function refresh() {
  try {
    const state = await api("/api/state");
    render(state);
    clearTimeout(pollTimer);
    if (state.phase === "analysing" || state.phase === "sending"
        || autofillRunning(state)) {
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
  try {
    await api("/api/analyse", { limit, links });
  } catch (error) {
    window.alert(error.message);
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
  try {
    await api("/api/send", {
      groups: [...selected],
      note: document.getElementById("note").value,
      delete: remove,
    });
  } catch (error) {
    window.alert(error.message);
  }
  refresh();
}

async function startAutofill(group, button) {
  button.disabled = true;
  try {
    await api("/api/autofill", { group: group.id });
  } catch (error) {
    window.alert(error.message);
  } finally {
    setTimeout(() => { button.disabled = false; }, 3000);
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
  } catch (error) {
    window.alert(error.message);
  }
  refresh();
}

async function quit() {
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
