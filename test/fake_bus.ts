// Fake Switchboard bus for the approve page's end-to-end tests.
//
// Implements the browser routes of the bus's page_api.md (v1.12 routes) with REAL WebAuthn
// verification (@simplewebauthn/server), in-memory state, and the contract's CORS
// rules for the page origin. It also serves the page itself on a second port, so
// page and bus are cross-origin exactly as in production.
//
//   deno run --allow-net --allow-read --allow-env test/fake_bus.ts
//
// Env: PAGE_PORT (default 8765), BUS_PORT (8766), PAGE_DIR (repo root).
// Test-control routes live under /__test/* (no CORS; the test runner calls them).

import { pageHandler, servePage } from "./serve_page.ts";

const lib = await import("jsr:@simplewebauthn/server@14.0.3");

const PAGE_PORT = Number(Deno.env.get("PAGE_PORT") ?? 8765);
const BUS_PORT = Number(Deno.env.get("BUS_PORT") ?? 8766);
const PAGE_DIR = Deno.env.get("PAGE_DIR") ?? new URL("..", import.meta.url).pathname;
const RP_ID = "localhost";
const PAGE_ORIGIN = `http://localhost:${PAGE_PORT}`;
const BUS_ORIGIN = `http://localhost:${BUS_PORT}`;
const CHALLENGE_TTL_MS = 300_000;
const PREFIX = "/functions/v1/switchboard";

// ---------------- state ----------------
interface Invite { name: string; expires: number; used: boolean }
interface Challenge { purpose: "register" | "device" | "list" | "decide" | "enroll_list" | "enroll_decide"; bound: string; expires: number; used: boolean }
interface Passkey { id: string; publicKey: Uint8Array; name: string; alg: string }
interface Device { status: "pending" | "approved" | "denied"; expires: number }
interface Approval {
  request_id: string; thread_id: string; from: string; created_at: string; body: string;
  context: { id: string; from: string; type: string; created_at: string; body: string }[];
  decided?: string;
}
interface Log { route: string; status: number; code?: string; body?: unknown }
// An enrollment row as the bus keeps it. `code` and `wrong` never leave the fake bus.
interface Enrollment {
  enrollment_id: string; requested_id: string; kind: string; platform: string; display_name: string;
  created_at: string; expires_at: string; replace: boolean; requested_by: string | null;
  reply_token: boolean; lookalike_of: string[];
  code: string; wrong: number; status: "pending" | "approved" | "denied";
}

let invites = new Map<string, Invite>();
let challenges = new Map<string, Challenge>();
let passkeys = new Map<string, Passkey>();
let devices = new Map<string, Device>();
let approvals = new Map<string, Approval>();
let decisions: { request_id: string; decision: string }[] = [];
let enrollments = new Map<string, Enrollment>();
let enrollRequests: Record<string, unknown>[] = []; // decide bodies minus the assertion
let enrollFailNext: string | null = null;
let log: Log[] = [];
let failNext: string | null = null;

function reset() {
  invites = new Map(); challenges = new Map(); passkeys = new Map(); devices = new Map();
  approvals = new Map(); decisions = []; log = []; failNext = null;
  enrollments = new Map(); enrollRequests = []; enrollFailNext = null;
}
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function enrollmentId(): string {
  const b = crypto.getRandomValues(new Uint8Array(26));
  return "enr_" + [...b].map((x) => CROCKFORD[x % 32]).join("");
}
const ENR_ID = /^enr_[0-9A-HJKMNP-TV-Z]{26}$/;
const ENROLL_DECIDE_KEYS = new Set(["enrollment_id", "decision", "code", "replace", "assertion"]);

function rand(n = 32): string {
  const b = crypto.getRandomValues(new Uint8Array(n));
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const ALPHA = "BCDFGHJKLMNPQRSTVWXZ";
function userCode(): string {
  const b = crypto.getRandomValues(new Uint8Array(8));
  const s = [...b].map((x) => ALPHA[x % ALPHA.length]).join("");
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}
const normCode = (c: unknown) => String(c ?? "").toUpperCase().replace(/[-\s]/g, "");

// ---------------- HTTP helpers ----------------
const CORS_ROUTES = new Set([
  "/v1/passkeys/register/options", "/v1/passkeys/register/verify", "/v1/passkeys/auth/options",
  "/v1/owner/device/approve", "/v1/owner/device/deny", "/v1/approvals/web/list", "/v1/approvals/web/decide",
  "/v1/enrollments/web/list", "/v1/enrollments/web/decide",
]);

function json(status: number, body: unknown, cors: boolean): Response {
  const h = new Headers({ "content-type": "application/json" });
  if (cors) {
    h.set("access-control-allow-origin", PAGE_ORIGIN);
    h.set("access-control-expose-headers", "Retry-After");
    h.set("vary", "Origin");
  }
  return new Response(JSON.stringify(body), { status, headers: h });
}
class HttpError extends Error {
  constructor(public status: number, public code: string, msg: string, public extra: Record<string, unknown> = {}) { super(msg); }
}
const fail = (status: number, code: string, msg: string, extra: Record<string, unknown> = {}): never => {
  throw new HttpError(status, code, msg, extra);
};

function b64urlDecode(s: string): Uint8Array {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
}
function challengeOf(resp: unknown): string {
  try {
    // deno-lint-ignore no-explicit-any
    const cdj = JSON.parse(new TextDecoder().decode(b64urlDecode((resp as any).response.clientDataJSON)));
    return String(cdj.challenge);
  } catch {
    return fail(422, "validation_failed", "Malformed credential.");
  }
}

// Take a challenge (single use even when verification later fails) and check its binding.
function takeChallenge(resp: unknown, purpose: Challenge["purpose"], bound: string): string {
  const ch = challengeOf(resp);
  const rec = challenges.get(ch);
  if (!rec || rec.used || rec.expires < Date.now()) fail(401, "bad_challenge", "Challenge unknown, used, or expired.");
  rec!.used = true;
  if (rec!.purpose !== purpose || rec!.bound !== bound) fail(401, "bad_challenge", "Challenge is bound to something else.");
  return ch;
}

async function verifyAssertion(assertion: unknown, purpose: Challenge["purpose"], bound: string) {
  if (!assertion || typeof assertion !== "object") fail(422, "validation_failed", "assertion is required.");
  const ch = takeChallenge(assertion, purpose, bound);
  if (failNext) { const code = failNext; failNext = null; fail(401, code, `Injected ${code}.`); }
  // deno-lint-ignore no-explicit-any
  const id = String((assertion as any).id ?? "");
  const pk = passkeys.get(id);
  if (!pk) fail(401, "bad_assertion", "Unknown passkey.");
  let ok = false;
  try {
    const r = await lib.verifyAuthenticationResponse({
      // deno-lint-ignore no-explicit-any
      response: assertion as any, expectedChallenge: ch, expectedOrigin: PAGE_ORIGIN, expectedRPID: RP_ID,
      credential: { id: pk!.id, publicKey: pk!.publicKey, counter: 0 }, requireUserVerification: true,
    });
    ok = r.verified;
  } catch (e) {
    fail(401, "bad_assertion", `Assertion rejected: ${(e as Error).message}`);
  }
  if (!ok) fail(401, "bad_assertion", "Assertion rejected.");
}

async function newAuthOptions(purpose: Challenge["purpose"], bound: string) {
  const options = await lib.generateAuthenticationOptions({ rpID: RP_ID, userVerification: "required", timeout: CHALLENGE_TTL_MS, allowCredentials: [] });
  const expires = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(options.challenge, { purpose, bound, expires, used: false });
  return { expires_at: new Date(expires).toISOString(), options };
}

// ---------------- bus routes ----------------
// deno-lint-ignore no-explicit-any
type Body = any;
async function route(path: string, b: Body): Promise<[number, unknown]> {
  switch (path) {
    case "/v1/passkeys/register/options": {
      if (typeof b.token !== "string") fail(422, "validation_failed", "token is required.");
      const inv = invites.get(b.token);
      if (!inv || inv.used || inv.expires < Date.now()) fail(401, "bad_invite", "Invite unknown, used, or expired.");
      const options = await lib.generateRegistrationOptions({
        rpName: "Switchboard", rpID: RP_ID, userName: "rz", userDisplayName: "rz (switchboard)",
        userID: new TextEncoder().encode("owner-rz"), attestationType: "none", timeout: CHALLENGE_TTL_MS,
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        supportedAlgorithmIDs: [-8, -7],
        excludeCredentials: [...passkeys.values()].map((p) => ({ id: p.id })),
        extensions: { credProps: true },
      });
      const expires = Date.now() + CHALLENGE_TTL_MS;
      challenges.set(options.challenge, { purpose: "register", bound: b.token, expires, used: false });
      return [200, { name: inv!.name, expires_at: new Date(expires).toISOString(), options }];
    }
    case "/v1/passkeys/register/verify": {
      if (typeof b.token !== "string" || !b.credential) fail(422, "validation_failed", "token and credential are required.");
      const inv = invites.get(b.token);
      if (!inv || inv.used || inv.expires < Date.now()) fail(401, "bad_invite", "Invite unknown, used, or expired.");
      const ch = takeChallenge(b.credential, "register", b.token);
      let info: Body;
      try {
        const r = await lib.verifyRegistrationResponse({
          response: b.credential, expectedChallenge: ch, expectedOrigin: PAGE_ORIGIN, expectedRPID: RP_ID,
          requireUserVerification: true, supportedAlgorithmIDs: [-8, -7],
        });
        if (!r.verified) fail(422, "bad_registration", "Registration not verified.");
        info = r.registrationInfo;
      } catch (e) {
        if (e instanceof HttpError) throw e;
        fail(422, "bad_registration", `Registration rejected: ${(e as Error).message}`);
      }
      const id = info.credential.id as string;
      if (passkeys.has(id)) fail(409, "duplicate_credential", "That passkey is already registered.");
      // COSE key map starts {1: kty, 3: alg, ...}; byte 4 is alg (0x26 = -7, 0x27 = -8).
      const algByte = (info.credential.publicKey as Uint8Array)[4];
      const alg = algByte === 0x26 ? "ES256" : algByte === 0x27 ? "EdDSA" : `other(${algByte})`;
      passkeys.set(id, { id, publicKey: info.credential.publicKey, name: inv!.name, alg });
      inv!.used = true;
      return [201, { name: inv!.name, owner_id: "rz", alg, backed_up: !!info.credentialBackedUp, created_at: new Date().toISOString() }];
    }
    case "/v1/passkeys/auth/options": {
      if (b.purpose === "device") {
        const d = devices.get(normCode(b.user_code));
        if (!d || d.status !== "pending" || d.expires < Date.now()) fail(404, "not_found", "Unknown or expired code.");
        return [200, await newAuthOptions("device", normCode(b.user_code))];
      }
      if (b.purpose === "list") return [200, await newAuthOptions("list", "")];
      if (b.purpose === "decide") {
        if (typeof b.request_id !== "string" || !b.request_id) fail(422, "validation_failed", "request_id is required.");
        if (b.decision !== "approve" && b.decision !== "deny") fail(422, "validation_failed", "decision must be approve or deny.");
        return [200, await newAuthOptions("decide", `${b.request_id}|${b.decision}`)];
      }
      if (b.purpose === "enroll_list") return [200, await newAuthOptions("enroll_list", "")];
      if (b.purpose === "enroll_decide") {
        // Options never look the enrollment up (SPEC), so they tell nothing about it.
        if (typeof b.enrollment_id !== "string" || !ENR_ID.test(b.enrollment_id)) fail(422, "validation_failed", "enrollment_id is required.");
        if (b.decision !== "approve" && b.decision !== "deny") fail(422, "validation_failed", "decision must be approve or deny.");
        return [200, await newAuthOptions("enroll_decide", `${b.enrollment_id}|${b.decision}`)];
      }
      return fail(422, "validation_failed", "purpose must be device, list, decide, enroll_list, or enroll_decide.");
    }
    case "/v1/owner/device/approve":
    case "/v1/owner/device/deny": {
      const code = normCode(b.user_code);
      if (!code) fail(422, "validation_failed", "user_code is required.");
      await verifyAssertion(b.assertion, "device", code);
      const d = devices.get(code);
      if (!d || d.expires < Date.now()) fail(404, "not_found", "Unknown or expired code.");
      if (d!.status !== "pending") fail(409, "already_decided", "Already decided.");
      d!.status = path.endsWith("approve") ? "approved" : "denied";
      return [200, { status: d!.status, user_code: `${code.slice(0, 4)}-${code.slice(4)}` }];
    }
    case "/v1/approvals/web/list": {
      await verifyAssertion(b.assertion, "list", "");
      const open = [...approvals.values()].filter((a) => !a.decided)
        .sort((x, y) => x.created_at.localeCompare(y.created_at)).slice(0, 50)
        .map(({ decided: _d, ...a }) => a);
      return [200, { owner_id: "rz", acts_as: "rz-operator", approvals: open }];
    }
    case "/v1/approvals/web/decide": {
      if (typeof b.request_id !== "string" || (b.decision !== "approve" && b.decision !== "deny")) {
        fail(422, "validation_failed", "request_id and decision are required.");
      }
      await verifyAssertion(b.assertion, "decide", `${b.request_id}|${b.decision}`);
      const a = approvals.get(b.request_id);
      if (!a) fail(422, "not_an_approval_request", "Unknown request.");
      if (a!.decided) fail(409, "already_decided", "Already decided.");
      a!.decided = b.decision;
      decisions.push({ request_id: b.request_id, decision: b.decision });
      return [201, { id: `msg_${rand(8)}`, created_at: new Date().toISOString(), request_id: b.request_id, decision: b.decision }];
    }
    case "/v1/enrollments/web/list": {
      if (!b.assertion || typeof b.assertion !== "object") fail(401, "bad_assertion", "assertion is required.");
      await verifyAssertion(b.assertion, "enroll_list", "");
      const now = Date.now();
      const live = [...enrollments.values()].filter((e) => e.status === "pending" && Date.parse(e.expires_at) > now)
        .sort((x, y) => x.created_at.localeCompare(y.created_at))
        .map(({ code: _c, wrong, status: _s, ...e }) => ({ ...e, code_tries_left: 3 - wrong }));
      return [200, { owner_id: "rz", acts_as: "rz-operator", enrollments: live }];
    }
    case "/v1/enrollments/web/decide": {
      // Checks in SPEC order; the first failure wins.
      if (!b.assertion || typeof b.assertion !== "object") fail(401, "bad_assertion", "assertion is required.");
      const { assertion: _a, ...seen } = b;
      enrollRequests.push(seen);
      for (const k of Object.keys(b)) if (!ENROLL_DECIDE_KEYS.has(k)) fail(422, "validation_failed", `unknown field ${k}.`);
      if (typeof b.enrollment_id !== "string" || !ENR_ID.test(b.enrollment_id)) fail(422, "validation_failed", "enrollment_id is invalid.");
      if (b.decision !== "approve" && b.decision !== "deny") fail(422, "validation_failed", "decision must be approve or deny.");
      if (b.replace !== undefined && typeof b.replace !== "boolean") fail(422, "validation_failed", "replace must be a boolean.");
      const digits = String(b.code ?? "").replace(/\D/g, "");
      if (b.decision === "approve" && (typeof b.code !== "string" || !/^(\d{4}|\d{6})$/.test(digits))) {
        fail(422, "validation_failed", "code must be 4 or 6 digits.");
      }
      await verifyAssertion(b.assertion, "enroll_decide", `${b.enrollment_id}|${b.decision}`);
      const e = enrollments.get(b.enrollment_id);
      if (!e || e.status !== "pending" || Date.parse(e.expires_at) <= Date.now()) fail(404, "not_found", "No live pending enrollment.");
      if (b.decision === "deny") { e!.status = "denied"; return [200, { status: "denied", enrollment_id: e!.enrollment_id }]; }
      if (digits !== e!.code) {
        e!.wrong++;
        if (e!.wrong >= 3) e!.status = "denied";
        fail(409, "code_mismatch", "Wrong code.", { tries_left: 3 - e!.wrong });
      }
      if (enrollFailNext) { const code = enrollFailNext; enrollFailNext = null; fail(409, code, `Injected ${code}.`); }
      if ((b.replace ?? false) !== e!.replace) fail(409, "replace_mismatch", "replace does not match the row.");
      e!.status = "approved";
      return [200, { status: "approved", agent_id: e!.requested_id, kind: e!.kind, replaced: e!.replace, reply_token: e!.reply_token }];
    }
  }
  return fail(404, "not_found", "Not found.");
}

// ---------------- test-control routes ----------------
function control(path: string, b: Body): unknown {
  switch (path) {
    case "/__test/reset": reset(); return { ok: true };
    case "/__test/invite": {
      const token = rand(32);
      invites.set(token, { name: b.name ?? "iPhone", expires: Date.now() + (b.ttl_ms ?? 600_000), used: false });
      return { token };
    }
    case "/__test/device": {
      const code = b.user_code ?? userCode();
      devices.set(normCode(code), { status: "pending", expires: Date.now() + (b.ttl_ms ?? 600_000) });
      return { user_code: code };
    }
    case "/__test/expire_device": {
      const d = devices.get(normCode(b.user_code));
      if (d) d.expires = 0;
      return { ok: !!d };
    }
    case "/__test/approval": {
      const id = b.request_id ?? `msg_${rand(8)}`;
      approvals.set(id, {
        request_id: id, thread_id: `thr_${rand(6)}`, from: b.from ?? "mac.switchboard.s1",
        created_at: b.created_at ?? new Date().toISOString(), body: b.body ?? "", context: b.context ?? [],
      });
      return { request_id: id };
    }
    case "/__test/enrollment": {
      const id = enrollmentId();
      const now = Date.now();
      enrollments.set(id, {
        enrollment_id: id, requested_id: b.requested_id ?? "muse", kind: b.kind ?? "agent",
        platform: b.platform ?? "meta-muse", display_name: b.display_name ?? "Muse",
        created_at: b.created_at ?? new Date(now).toISOString(),
        expires_at: new Date(now + (b.ttl_ms ?? 600_000)).toISOString(),
        replace: b.replace ?? false, requested_by: "requested_by" in b ? b.requested_by : "rz-operator.s1",
        reply_token: b.reply_token ?? false, lookalike_of: b.lookalike_of ?? [],
        code: b.code ?? "4829", wrong: 0, status: "pending",
      });
      return { enrollment_id: id };
    }
    case "/__test/enrollment_status": {
      // Decide a row behind the page's back (e.g. approved from the CLI meanwhile).
      const e = enrollments.get(b.enrollment_id);
      if (e) e.status = b.status ?? "approved";
      return { ok: !!e };
    }
    case "/__test/enroll_fail_next":
      enrollFailNext = String(b.code ?? "id_contested");
      return { ok: true };
    case "/__test/fail_next":
      failNext = String(b.code ?? "bad_assertion");
      return { ok: true };
    case "/__test/state":
      return {
        enrollments: Object.fromEntries([...enrollments].map(([k, v]) => [k, v.status])), enroll_requests: enrollRequests,
        passkeys: passkeys.size, decisions,
        devices: Object.fromEntries([...devices].map(([k, v]) => [k, v.status])), log,
      };
  }
  return { error: "unknown control route" };
}

async function busHandler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) : url.pathname;
  const origin = req.headers.get("origin");
  if (path.startsWith("/__test/")) {
    const b = req.method === "POST" ? await req.json().catch(() => ({})) : {};
    return json(200, control(path, b), false);
  }
  if (path === "/health") return json(200, { ok: true, passkeys: true, passkeys_rp_id: RP_ID }, false);
  const browser = CORS_ROUTES.has(path);
  if (req.method === "OPTIONS") {
    if (!browser) return new Response(null, { status: 404 });
    if (origin !== PAGE_ORIGIN) {
      return new Response(JSON.stringify({ error: "Forbidden origin.", code: "forbidden_origin" }), { status: 403, headers: { vary: "Origin", "content-type": "application/json" } });
    }
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": PAGE_ORIGIN, "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type", "access-control-max-age": "600", vary: "Origin",
      },
    });
  }
  if (browser && origin !== null && origin !== PAGE_ORIGIN) {
    return new Response(JSON.stringify({ error: "Forbidden origin.", code: "forbidden_origin" }), { status: 403, headers: { vary: "Origin", "content-type": "application/json" } });
  }
  const cors = browser && origin === PAGE_ORIGIN;
  if (req.method !== "POST") return json(404, { error: "Not found.", code: "not_found" }, cors);
  let body: Body;
  try {
    body = await req.json();
    if (!body || typeof body !== "object") throw new Error("not an object");
  } catch {
    log.push({ route: path, status: 422, code: "validation_failed" });
    return json(422, { error: "Body must be a JSON object.", code: "validation_failed" }, cors);
  }
  try {
    const [status, out] = await route(path, body);
    log.push({ route: path, status, body: path === "/v1/passkeys/auth/options" ? body : undefined });
    return json(status, out, cors);
  } catch (e) {
    if (e instanceof HttpError) {
      log.push({ route: path, status: e.status, code: e.code, body: path === "/v1/passkeys/auth/options" ? body : undefined });
      return json(e.status, { error: e.message, code: e.code, ...e.extra }, cors);
    }
    console.error(e);
    return json(500, { error: "Internal error.", code: "internal" }, cors);
  }
}

Deno.serve({ port: BUS_PORT, hostname: "127.0.0.1", onListen: () => {} }, busHandler);
Deno.serve({ port: BUS_PORT, hostname: "::1", onListen: () => {} }, busHandler);
servePage(PAGE_PORT, pageHandler(PAGE_DIR, BUS_ORIGIN));
console.log(`fake bus ${BUS_ORIGIN}${PREFIX}  page ${PAGE_ORIGIN}  rp ${RP_ID}`);
