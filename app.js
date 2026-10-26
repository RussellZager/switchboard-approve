// Switchboard approve page: add a passkey, confirm a CLI login code, approve or deny
// agent requests. Plain ES module, no framework, no third-party code.
//
// Safety rules:
// - Agent-written text is untrusted. It only ever reaches the DOM as text nodes
//   (textContent / createTextNode). This file never uses innerHTML or similar.
// - URLs in agent text stay text; nothing here creates links.
// - Nothing is stored: no cookies, no localStorage. Every action asks for a fresh
//   passkey assertion whose server challenge is bound to that one action.

import { BUS_BASE } from "./config.js";

const app = document.getElementById("app");

// ---------------------------------------------------------------- DOM helpers
// h("p", {class: "x"}, "text", node) -> element. Strings become text nodes.
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "onclick") el.addEventListener("click", v);
    else if (k === "hidden") el.hidden = true;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}
function setText(el, text) { el.textContent = text; }
function render(...nodes) { app.replaceChildren(h("h1", { class: "brand" }, "Switchboard"), ...nodes); }

// ------------------------------------------------------------- base64url codec
function b64uToBuf(s) {
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --------------------------------------------------- WebAuthn JSON conversion
// Prefer the browser's own JSON helpers; fall back to converting by hand.
function creationOptions(json) {
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
    return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  }
  return {
    ...json,
    challenge: b64uToBuf(json.challenge),
    user: { ...json.user, id: b64uToBuf(json.user.id) },
    excludeCredentials: (json.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
}
function requestOptions(json) {
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
    return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  }
  return {
    ...json,
    challenge: b64uToBuf(json.challenge),
    allowCredentials: (json.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
}
function credentialJSON(cred) {
  if (typeof cred.toJSON === "function") return cred.toJSON();
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: { clientDataJSON: bufToB64u(r.clientDataJSON) },
  };
  if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
  if (r.attestationObject) {
    out.response.attestationObject = bufToB64u(r.attestationObject);
    if (typeof r.getTransports === "function") out.response.transports = r.getTransports();
  } else {
    out.response.authenticatorData = bufToB64u(r.authenticatorData);
    out.response.signature = bufToB64u(r.signature);
    if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
  }
  return out;
}

// -------------------------------------------------------------------- bus API
// data: the parsed error body (e.g. tries_left), or null.
class ApiError extends Error {
  constructor(status, code, data = null) { super(code); this.status = status; this.code = code; this.data = data; }
}
async function post(path, body) {
  let res;
  try {
    res = await fetch(BUS_BASE + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new ApiError(0, "network");
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON body */ }
  if (!res.ok) throw new ApiError(res.status, (data && typeof data.code === "string" && data.code) || `http_${res.status}`, data);
  return data;
}

const AUTH_OPTIONS = "/v1/passkeys/auth/options";

function needPasskeys() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new DOMException("no webauthn", "NotSupportedError");
  }
}
// Both start the browser's passkey prompt synchronously, before their first await.
async function createPasskey(optionsJSON) {
  needPasskeys();
  const cred = await navigator.credentials.create({ publicKey: creationOptions(optionsJSON) });
  if (!cred) throw new DOMException("no credential", "NotAllowedError");
  return credentialJSON(cred);
}
async function getAssertion(optionsJSON) {
  needPasskeys();
  const cred = await navigator.credentials.get({ publicKey: requestOptions(optionsJSON) });
  if (!cred) throw new DOMException("no credential", "NotAllowedError");
  return credentialJSON(cred);
}

// ------------------------------------------------ prefetched passkey options
// Safari can refuse navigator.credentials.* when an awaited fetch runs between
// the tap and the call. So the options (with their server challenge) are fetched
// BEFORE the tap, and a tap starts the prompt at once.
// Challenges live 300 s; after FRESH_MS the page gets a new one and asks for one
// more tap. It never retries on its own.
const FRESH_MS = 240_000;
class Ticket {
  constructor(path, body) {
    this.path = path;
    this.body = body;
    this.state = "idle"; // idle | loading | ready | used | failed
    this.options = null;
    this.at = 0;
    this.error = null;
    this.seq = 0;
    this.listeners = [];
  }
  on(fn) { this.listeners.push(fn); }
  emit() { for (const fn of this.listeners) fn(this); }
  load() {
    const seq = ++this.seq;
    this.state = "loading";
    this.options = null;
    this.error = null;
    this.emit();
    post(this.path, this.body).then((data) => {
      if (seq !== this.seq) return;
      this.options = data && data.options;
      this.at = Date.now();
      this.state = "ready";
      this.emit();
    }, (err) => {
      if (seq !== this.seq) return;
      this.error = err;
      this.state = "failed";
      this.emit();
    });
  }
  ensure() { if (this.state === "idle") this.load(); }
  // Synchronous. Fresh options, single use; null when not ready or too old.
  take() {
    if (this.state !== "ready" || Date.now() - this.at > FRESH_MS) return null;
    const options = this.options;
    this.state = "used";
    this.options = null;
    this.emit();
    return options;
  }
}

// ------------------------------------------------------------ plain-word errors
// tries_left from a 409 code_mismatch, or null when the bus sent none.
function triesLeft(err) {
  const n = err && err.data && err.data.tries_left;
  return Number.isInteger(n) && n >= 0 ? n : null;
}
// ctx: "register" | "device" | "list" | "decide" | "enroll". Returns { text, retry, button }.
// button:false means no Retry button: the user fixes something (the code) and taps the
// action again; a fresh challenge is still fetched for that tap.
function explain(err, ctx) {
  if (err instanceof DOMException) {
    switch (err.name) {
      case "NotAllowedError":
      case "AbortError": return { text: "Passkey cancelled.", retry: true };
      case "InvalidStateError": return { text: "This device already has a passkey.", retry: false };
      case "NotSupportedError": return { text: "This browser can't use passkeys.", retry: false };
      case "SecurityError": return { text: "Passkeys don't work on this address.", retry: false };
    }
    return { text: "Passkey problem. Try again.", retry: true };
  }
  if (!(err instanceof ApiError)) return { text: "Something went wrong. Try again.", retry: true };
  switch (err.code) {
    case "network": return { text: "Network problem. Try again.", retry: true };
    case "rate_limited": return { text: "Too many tries. Wait a minute, then try again.", retry: true };
    case "unavailable": return { text: "Server busy. Try again.", retry: true };
    case "bad_challenge": return { text: "That took too long. Try again.", retry: true };
    case "bad_invite": return { text: "That link expired. Run switchboard passkey add again.", retry: false };
    case "duplicate_credential": return { text: "This passkey is already added.", retry: false };
    case "name_taken": return { text: "That name is taken. Run switchboard passkey add with another name.", retry: false };
    case "bad_registration": return { text: "Passkey not accepted. Try again.", retry: true };
    case "bad_assertion": return { text: "Passkey not recognized. Try again, or run switchboard passkey add.", retry: true };
    case "code_mismatch": {
      const n = triesLeft(err);
      if (n === 0) return { text: "Denied after 3 wrong codes.", retry: false };
      return { text: n === null ? "Wrong code." : `Wrong code. ${n} ${n === 1 ? "try" : "tries"} left.`, retry: true, button: false };
    }
    case "id_contested": return { text: "Two requests ask for this ID, and one may not be your agent. Deny, then ask your agent to enroll again.", retry: true, button: false };
    case "replace_mismatch": return { text: "This request no longer matches the agent list. Ask the agent to enroll again.", retry: false };
    case "duplicate_key": return { text: "That agent key is already in use. Ask the agent to enroll again.", retry: false };
    case "already_registered": return { text: "That ID is already taken. Ask the agent to enroll again.", retry: false };
    case "validation_failed":
      if (ctx === "enroll") return { text: "That code looks wrong. Type the digits the agent shows.", retry: true, button: false };
      break;
    case "not_found":
      if (ctx === "enroll") return { text: "No longer pending.", retry: false };
      if (ctx === "device") return { text: "That code expired. Run switchboard login again.", retry: false };
      return { text: "Not available. Try again later.", retry: false };
    case "already_decided":
      if (ctx === "device") return { text: "That code was already used. Run switchboard login again.", retry: false };
      return { text: "Already decided.", retry: false };
    case "not_an_approval_request": return { text: "That request is gone.", retry: false };
  }
  return { text: "Something went wrong. Try again.", retry: true };
}

// An error line with an optional Retry button. Returns { el, retryEl, show(err, again), clear() }.
function errorLine(ctx) {
  const text = h("span", { class: "error-text" });
  const retry = h("button", { type: "button", class: "retry", hidden: true }, "Retry");
  const el = h("p", { class: "error", role: "alert", hidden: true }, text, retry);
  let onRetry = null;
  retry.addEventListener("click", () => { if (onRetry) onRetry(); });
  return {
    el,
    retryEl: retry,
    show(err, again) {
      const { text: msg, retry: canRetry, button } = explain(err, ctx);
      setText(text, msg);
      onRetry = again;
      retry.hidden = !(canRetry && again && button !== false);
      el.hidden = false;
      return canRetry;
    },
    clear() { el.hidden = true; retry.hidden = true; setText(text, ""); onRetry = null; },
  };
}

// Wire buttons to prefetched options: pairs = [[button, ticket], ...].
// A tap (or a Retry tap) calls prompt(options) with no await before it; then
// after(button, credentialJSON) finishes the job. Buttons stay disabled until
// their options are ready. A final error (no Retry, e.g. an expired code) hides
// the buttons, because pressing them again cannot work. gate(button) can keep a
// button disabled until the page's own inputs are valid; call sync() when they change.
// snapshot(button) runs at the tap; its value is after()'s third argument, so input
// edited while the prompt is open cannot change what is sent. onBusy(on) runs when
// a prompt starts and when the job ends.
function passkeyButtons({ errs, pairs, prompt, after, reloadAfter = false, gate = () => true, snapshot = () => undefined, onBusy = () => {} }) {
  const buttons = pairs.map(([b]) => b);
  const tickets = [...new Set(pairs.map(([, t]) => t))];
  let busy = false;
  let waitFor = null; // the ticket the visible Retry needs
  let loadError = false; // the visible error came from fetching options
  const sync = () => {
    for (const [b, t] of pairs) b.disabled = busy || t.state !== "ready" || !gate(b);
    errs.retryEl.disabled = busy || (waitFor !== null && waitFor.state === "loading");
  };
  const stop = () => { for (const b of buttons) b.hidden = true; };

  for (const t of tickets) {
    t.on(() => {
      if (t.state === "failed") {
        loadError = true;
        waitFor = t;
        if (!errs.show(t.error, () => t.load())) stop();
      } else if (t.state === "ready" && loadError && waitFor === t) {
        loadError = false;
        waitFor = null;
        errs.clear();
      }
      sync();
    });
  }

  function tap(b, t) {
    if (busy || !gate(b)) return;
    const options = t.take();
    if (!options) {
      if (t.state === "ready") {
        // Older than FRESH_MS: get a new challenge and ask for one more tap.
        t.load();
        loadError = false;
        waitFor = t;
        errs.show(new ApiError(401, "bad_challenge"), () => tap(b, t));
        sync();
      }
      return;
    }
    errs.clear();
    loadError = false;
    waitFor = null;
    const snap = snapshot(b);
    let cred;
    try { cred = prompt(options); } catch (e) { cred = Promise.reject(e); }
    busy = true;
    onBusy(true);
    app.setAttribute("aria-busy", "true");
    sync();
    (async () => {
      try {
        await after(b, await cred, snap);
        if (reloadAfter) t.load();
      } catch (err) {
        waitFor = t;
        const canRetry = errs.show(err, () => tap(b, t));
        if (canRetry) t.load(); // a new challenge for the Retry tap
        else stop();
      } finally {
        busy = false;
        onBusy(false);
        app.removeAttribute("aria-busy");
        sync();
      }
    })();
  }

  for (const [b, t] of pairs) b.addEventListener("click", () => tap(b, t));
  sync();
  return { load() { for (const t of tickets) t.ensure(); }, sync };
}

function done(message) {
  render(h("p", { class: "result", role: "status" }, message));
}

// ------------------------------------------------------------ mode: register
function registerMode(token) {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(token)) {
    render(h("p", { class: "error", role: "alert" }, "That link looks wrong. Run switchboard passkey add again."));
    return;
  }
  const errs = errorLine("register");
  const add = h("button", { type: "button", class: "primary" }, "Add passkey");
  const ticket = new Ticket("/v1/passkeys/register/options", { token });
  render(add, errs.el);
  passkeyButtons({
    errs, pairs: [[add, ticket]], prompt: createPasskey,
    after: async (_b, credential) => {
      await post("/v1/passkeys/register/verify", { token, credential });
      done("Passkey added. You can close this page.");
    },
  }).load();
}

// ---------------------------------------------------------- mode: device code
const CODE_ALPHABET = /^[BCDFGHJKLMNPQRSTVWXZ]{8}$/;
const normCode = (raw) => String(raw).toUpperCase().replace(/[-\s]/g, "");
function codeMode(raw) {
  const norm = normCode(raw);
  if (!CODE_ALPHABET.test(norm)) {
    render(h("p", { class: "error", role: "alert" }, "That code looks wrong. Run switchboard login again."));
    return;
  }
  const code = `${norm.slice(0, 4)}-${norm.slice(4)}`;
  const errs = errorLine("device");
  const confirm = h("button", { type: "button", class: "primary" }, "Confirm");
  const notMe = h("button", { type: "button", class: "secondary" }, "Not me");
  const routes = new Map([
    [confirm, ["/v1/owner/device/approve", "Signed in on your Mac. You can close this page."]],
    [notMe, ["/v1/owner/device/deny", "Sign-in blocked. You can close this page."]],
  ]);
  // One device challenge serves either button (it is bound to the code only).
  const ticket = new Ticket(AUTH_OPTIONS, { purpose: "device", user_code: code });
  render(
    h("p", { class: "label", id: "code-label" }, "Code on your Mac"),
    h("p", { class: "code", "aria-labelledby": "code-label" }, code),
    h("p", { class: "warn" }, "Only confirm if you just ran switchboard login and this code matches."),
    h("div", { class: "actions" }, confirm, notMe),
    errs.el,
  );
  passkeyButtons({
    errs, pairs: [[confirm, ticket], [notMe, ticket]], prompt: getAssertion,
    after: async (b, assertion) => {
      const [route, message] = routes.get(b);
      await post(route, { user_code: code, assertion });
      done(message);
    },
  }).load();
}

// ------------------------------------------------------------ mode: approvals
function age(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "now";
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}
function firstLine(text) {
  const line = String(text ?? "").split(/\r?\n/).find((l) => l.trim()) ?? "";
  return line.trim().slice(0, 200) || "(no text)";
}
const str = (v) => (typeof v === "string" ? v : "");

// The bus cuts each body to BODY_CAP characters (code points) and sends no flag
// (page_api.md). Honour a flag if one appears; else text at the cap was cut.
const BODY_CAP = 2000;
function wasShortened(text, item) {
  if (item && (item.truncated === true || item.body_truncated === true)) return true;
  return Array.from(text).length >= BODY_CAP;
}
function markShortened(el, text, item) {
  if (wasShortened(text, item)) el.append(" ", h("span", { class: "shortened" }, "(shortened)"));
}

let rowSeq = 0;
function requestItem(a) {
  const id = `req-${++rowSeq}`;
  const badge = h("span", { class: "badge", hidden: true });
  const row = h("button", { type: "button", class: "row", "aria-expanded": "false", "aria-controls": id },
    h("span", { class: "row-top" },
      h("span", { class: "from" }, str(a.from) || "(unknown)"),
      badge,
      h("time", { class: "age", datetime: str(a.created_at) }, age(a.created_at))),
    h("span", { class: "first" }, firstLine(a.body)));

  const bodyEl = h("p", { class: "body" });
  setText(bodyEl, str(a.body));
  markShortened(bodyEl, str(a.body), a);
  const context = Array.isArray(a.context) ? a.context : [];
  const ctxEls = context.map((c) => {
    const p = h("p", { class: "body" });
    setText(p, str(c && c.body));
    markShortened(p, str(c && c.body), c);
    return h("div", { class: "ctx" },
      h("p", { class: "ctx-meta" }, `${str(c && c.from)} · ${age(c && c.created_at)}`), p);
  });

  const errs = errorLine("decide");
  const approve = h("button", { type: "button", class: "primary" }, "Approve");
  const deny = h("button", { type: "button", class: "secondary" }, "Deny");
  const actions = h("div", { class: "actions" }, approve, deny);
  const finish = (label) => {
    actions.remove();
    setText(badge, label);
    badge.hidden = false;
    badge.className = `badge ${label === "Approved" ? "ok" : label === "Denied" ? "no" : ""}`;
  };
  // Each decision has its own challenge, bound to request_id + decision.
  const decideTicket = (decision) => new Ticket(AUTH_OPTIONS, { purpose: "decide", request_id: a.request_id, decision });
  const decisionOf = new Map([[approve, "approve"], [deny, "deny"]]);
  const wired = passkeyButtons({
    errs, pairs: [[approve, decideTicket("approve")], [deny, decideTicket("deny")]], prompt: getAssertion,
    after: async (b, assertion) => {
      const decision = decisionOf.get(b);
      try {
        await post("/v1/approvals/web/decide", { request_id: a.request_id, decision, assertion });
      } catch (err) {
        if (err instanceof ApiError && err.code === "already_decided") { finish("Already decided"); return; }
        throw err;
      }
      finish(decision === "approve" ? "Approved" : "Denied");
    },
  });

  const detail = h("div", { class: "detail", id, hidden: true },
    bodyEl,
    ctxEls.length ? h("div", { class: "context", "aria-label": "Earlier messages" }, ctxEls) : null,
    actions, errs.el);
  row.addEventListener("click", () => {
    const open = detail.hidden;
    detail.hidden = !open;
    row.setAttribute("aria-expanded", String(open));
    if (open) wired.load(); // fetch both decision challenges before Approve/Deny can be tapped
  });
  return h("li", { class: "item", "data-request-id": str(a.request_id) }, row, detail);
}

// "Have a code?": the fallback when the CLI cannot open the browser.
function codeEntry() {
  const input = h("input", {
    id: "code-in", type: "text", autocomplete: "off", autocapitalize: "characters",
    spellcheck: "false", maxlength: "12", placeholder: "XXXX-XXXX",
  });
  const open = h("button", { type: "button", class: "secondary open" }, "Open");
  const bad = h("p", { class: "error", role: "alert", hidden: true }, "That code looks wrong.");
  const go = () => {
    const norm = normCode(input.value);
    if (!CODE_ALPHABET.test(norm)) { bad.hidden = false; return; }
    location.hash = `code=${norm.slice(0, 4)}-${norm.slice(4)}`;
  };
  open.addEventListener("click", go);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  input.addEventListener("input", () => { bad.hidden = true; });
  return h("div", { class: "have-code" },
    h("label", { class: "label", for: "code-in" }, "Have a code?"),
    h("div", { class: "code-entry" }, input, open),
    bad);
}

function listMode() {
  const errs = errorLine("list");
  const show = h("button", { type: "button", class: "primary" }, "Show requests");
  const out = h("div", { class: "requests" });
  const ticket = new Ticket(AUTH_OPTIONS, { purpose: "list" });
  render(show, errs.el, out, enrollmentsSection(), codeEntry());
  passkeyButtons({
    errs, pairs: [[show, ticket]], prompt: getAssertion, reloadAfter: true,
    after: async (_b, assertion) => {
      const data = await post("/v1/approvals/web/list", { assertion });
      const items = Array.isArray(data && data.approvals) ? data.approvals : [];
      out.replaceChildren(items.length
        ? h("ul", { class: "list", "aria-label": "Requests" }, items.map(requestItem))
        : h("p", { class: "muted" }, "No requests."));
      setText(show, "Refresh");
      show.className = "secondary";
    },
  }).load();
}

// ---------------------------------------------------------- mode: enrollments
// An agent asks to join the bus; the owner approves it here by typing the code the
// agent shows. The bus never sends that code to this page, and the URL never carries it.
const ENR_ID = /^enr_[0-9A-HJKMNP-TV-Z]{26}$/;
const CODE_OK = /^(\d{4}|\d{6})$/;
const codeDigits = (raw) => String(raw).replace(/\D/g, "");
const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x) : []);
// Agent IDs are lower-case ASCII words joined by "-". The bus validates them; the page
// checks again, so a malformed row (bidi, zero-width, upper case) can only be denied.
const AGENT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const malformedRow = (row) => !AGENT_ID.test(str(row.requested_id)) ||
  (row.lookalike_of != null && (!Array.isArray(row.lookalike_of) ||
    row.lookalike_of.some((x) => typeof x !== "string" || !AGENT_ID.test(x))));
const idSpan = (x) => h("span", { class: "id" }, x);
function until(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "unknown";
  const s = (t - Date.now()) / 1000;
  if (s <= 0) return "expired";
  if (s < 60) return "in under a minute";
  if (s < 3600) return `in ${Math.ceil(s / 60)} min`;
  return `in ${Math.floor(s / 3600)} h`;
}
// [dt, dd]; the value (agent text) goes in as text only.
function field(label, value) {
  const dd = h("dd");
  setText(dd, value);
  return [h("dt", {}, label), dd];
}
async function listEnrollments(assertion) {
  const data = await post("/v1/enrollments/web/list", { assertion });
  const rows = Array.isArray(data && data.enrollments) ? data.enrollments : [];
  return rows.filter((r) => r && typeof r === "object");
}

// One enrollment: fields, warnings, the code box, Approve and Deny.
// Returns { el, load() }. onFinish(label) runs once, when the row is decided or gone.
function enrollmentDetail(row, onFinish = () => {}) {
  const uid = `enr-${++rowSeq}`;
  const id = str(row.requested_id);
  const lookalikes = strList(row.lookalike_of);
  const replace = row.replace === true;
  const malformed = malformedRow(row);
  const tries = field("Code tries left", String(Number.isInteger(row.code_tries_left) ? row.code_tries_left : 3));

  const confirmBox = h("input", { type: "checkbox", id: `${uid}-confirm` });
  const lookalikeWarn = lookalikes.length ? h("div", { class: "alert", role: "note" },
    h("p", { class: "alert-title" }, "Similar ID"),
    h("p", {}, idSpan(id), " looks like ", lookalikes.flatMap((x, i) => (i ? [", ", idSpan(x)] : [idSpan(x)])),
      ". Check this is the agent you expect, not a copy."),
    malformed ? null : h("label", { class: "confirm", for: `${uid}-confirm` }, confirmBox, "I checked: this is the agent I expect.")) : null;
  const malformedWarn = malformed ? h("p", { class: "alert" }, "This request looks malformed. Deny it.") : null;
  const replaceWarn = replace
    ? h("p", { class: "alert" }, `This replaces the existing agent ${id}; its old key stops working.`)
    : null;

  const codeIn = h("input", {
    id: `${uid}-code`, type: "text", inputmode: "numeric", autocomplete: "off",
    spellcheck: "false", maxlength: "12", placeholder: "Code",
  });
  const approve = h("button", { type: "button", class: "primary" }, "Approve");
  const deny = h("button", { type: "button", class: "secondary" }, "Deny");
  const controls = h("div", { class: "enroll-controls" },
    malformed ? null : h("label", { class: "label", for: `${uid}-code` }, "Code the agent shows"),
    malformed ? null : h("div", { class: "code-entry" }, codeIn),
    h("div", { class: "actions" }, malformed ? null : approve, deny));
  const errs = errorLine("enroll");
  const result = h("p", { class: "result", role: "status", hidden: true });

  let finished = false;
  const finish = (label, message) => {
    if (finished) return;
    finished = true;
    controls.remove();
    confirmBox.disabled = true;
    errs.clear();
    setText(result, message);
    result.className = `result ${label === "Approved" ? "" : label === "Denied" ? "no" : "gone"}`;
    result.hidden = false;
    onFinish(label);
    // The view went away (Refresh, hashchange) while the decide ran: keep the result visible.
    if (!el.isConnected) app.append(h("p", { class: result.className, role: "status" }, idSpan(id), `: ${message}`));
  };

  // Each decision has its own challenge, bound to enrollment_id + decision.
  const decideTicket = (decision) => new Ticket(AUTH_OPTIONS, { purpose: "enroll_decide", enrollment_id: row.enrollment_id, decision });
  const decisionOf = new Map([[approve, "approve"], [deny, "deny"]]);
  const wired = passkeyButtons({
    errs, prompt: getAssertion,
    pairs: malformed ? [[deny, decideTicket("deny")]] : [[approve, decideTicket("approve")], [deny, decideTicket("deny")]],
    // Approve needs a well-formed code and, for a similar ID, the extra confirm. Deny needs neither.
    gate: (b) => b !== approve || (CODE_OK.test(codeDigits(codeIn.value)) && (!lookalikes.length || confirmBox.checked)),
    snapshot: () => ({ code: codeDigits(codeIn.value), confirmed: confirmBox.checked }),
    onBusy: (on) => { codeIn.disabled = on; confirmBox.disabled = on || finished; },
    after: async (b, assertion, snap) => {
      const decision = decisionOf.get(b);
      // The code and the confirm as they were at the tap, not as they are now.
      if (decision === "approve" && !(CODE_OK.test(snap.code) && (!lookalikes.length || snap.confirmed))) throw new Error("approve gate");
      const body = decision === "approve"
        ? { enrollment_id: row.enrollment_id, decision, code: snap.code, replace, assertion }
        : { enrollment_id: row.enrollment_id, decision, assertion };
      let data;
      try {
        data = await post("/v1/enrollments/web/decide", body);
      } catch (err) {
        if (err instanceof ApiError && err.code === "not_found") { finish("Gone", "No longer pending."); return; }
        if (err instanceof ApiError && err.code === "code_mismatch") {
          const left = triesLeft(err);
          if (left !== null) setText(tries[1], String(left));
          codeIn.value = "";
          if (left === 0) { finish("Denied", "Denied after 3 wrong codes."); return; }
        }
        throw err; // shown with a fresh challenge prefetched for the next tap
      }
      if (data && data.status === "approved") {
        const agent = str(data.agent_id) || id;
        finish("Approved", data.reply_token === true ? `Approved ${agent}. Reply-only key stored.` : `Approved ${agent}.`);
      } else {
        finish("Denied", "Denied.");
      }
    },
  });
  codeIn.addEventListener("input", wired.sync);
  confirmBox.addEventListener("change", wired.sync);

  const el = h("div", { class: "enroll" },
    h("p", { class: "label" }, "Agent ID"),
    h("p", { class: "enroll-id" }, id || "(none)"),
    malformedWarn,
    lookalikeWarn,
    replaceWarn,
    h("dl", { class: "fields" },
      field("Kind", str(row.kind)),
      field("Platform", str(row.platform)),
      field("Name", str(row.display_name)),
      field("Requested by", row.requested_by === null ? "the full window" : str(row.requested_by)),
      field("Expires", until(row.expires_at)),
      tries),
    controls, errs.el, result);
  return { el, load: wired.load, uid };
}

function enrollmentItem(row) {
  const badge = h("span", { class: "badge", hidden: true });
  const flags = [
    malformedRow(row) ? h("span", { class: "flag" }, "malformed") : null,
    strList(row.lookalike_of).length ? h("span", { class: "flag" }, "similar ID") : null,
    row.replace === true ? h("span", { class: "flag" }, "replaces") : null,
  ];
  const d = enrollmentDetail(row, (label) => {
    setText(badge, label);
    badge.hidden = false;
    badge.className = `badge ${label === "Approved" ? "ok" : label === "Denied" ? "no" : ""}`;
  });
  const detail = h("div", { class: "detail", id: `${d.uid}-detail`, hidden: true }, d.el);
  const btn = h("button", { type: "button", class: "row", "aria-expanded": "false", "aria-controls": detail.id },
    h("span", { class: "row-top" },
      h("span", { class: "from" }, str(row.requested_id) || "(unknown)"),
      flags, badge,
      h("time", { class: "age", datetime: str(row.created_at) }, age(row.created_at))),
    h("span", { class: "first" }, [str(row.display_name), str(row.platform)].filter(Boolean).join(" · ") || "(no name)"));
  btn.addEventListener("click", () => {
    const open = detail.hidden;
    detail.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
    if (open) d.load(); // fetch both decision challenges before Approve/Deny can be tapped
  });
  return h("li", { class: "item", "data-enrollment-id": str(row.enrollment_id) }, btn, detail);
}

// Root page: the Enrollments list, next to the requests list.
function enrollmentsSection() {
  const errs = errorLine("enroll");
  const show = h("button", { type: "button", class: "primary" }, "Show enrollments");
  const out = h("div", { class: "requests" });
  const ticket = new Ticket(AUTH_OPTIONS, { purpose: "enroll_list" });
  passkeyButtons({
    errs, pairs: [[show, ticket]], prompt: getAssertion, reloadAfter: true,
    after: async (_b, assertion) => {
      const rows = await listEnrollments(assertion);
      out.replaceChildren(rows.length
        ? h("ul", { class: "list", "aria-label": "Enrollments" }, rows.map(enrollmentItem))
        : h("p", { class: "muted" }, "No enrollments."));
      setText(show, "Refresh enrollments");
      show.className = "secondary";
    },
  }).load();
  return h("section", { class: "enrollments", "aria-labelledby": "enrollments-h" },
    h("h2", { class: "section", id: "enrollments-h" }, "Enrollments"), show, errs.el, out);
}

// #enroll=<enrollment_id>: one enrollment, from the list the passkey unlocks.
function enrollMode(enrollmentId) {
  if (!ENR_ID.test(enrollmentId)) {
    render(h("p", { class: "error", role: "alert" }, "That link looks wrong."));
    return;
  }
  const errs = errorLine("enroll");
  const show = h("button", { type: "button", class: "primary" }, "Show request");
  const out = h("div", { class: "enroll-one" });
  const ticket = new Ticket(AUTH_OPTIONS, { purpose: "enroll_list" });
  render(h("p", { class: "label" }, "An agent asks to join Switchboard"), show, errs.el, out);
  passkeyButtons({
    errs, pairs: [[show, ticket]], prompt: getAssertion,
    after: async (_b, assertion) => {
      const rows = await listEnrollments(assertion);
      const row = rows.find((r) => r.enrollment_id === enrollmentId);
      show.hidden = true;
      if (!row) {
        out.replaceChildren(h("p", { class: "result gone", role: "status" }, "No longer pending."));
        return;
      }
      const d = enrollmentDetail(row);
      out.replaceChildren(d.el);
      d.load();
    },
  }).load();
}

// ------------------------------------------------------------------- routing
function start() {
  if (window.top !== window.self) {
    render(h("p", { class: "error", role: "alert" }, "Open this page directly."));
    return;
  }
  const params = new URLSearchParams(location.hash.slice(1));
  if (params.has("enroll")) enrollMode(params.get("enroll") ?? "");
  else if (params.has("register")) registerMode(params.get("register") ?? "");
  else if (params.has("code")) codeMode(params.get("code") ?? "");
  else listMode();
}

window.addEventListener("hashchange", start);
start();
