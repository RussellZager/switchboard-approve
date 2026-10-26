// End-to-end tests for the approve page against test/fake_bus.ts (real WebAuthn
// verification) with Chrome's CDP virtual authenticator.
import { expect, test, type CDPSession, type Page } from "@playwright/test";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { BUS_PORT, PAGE_PORT } from "../playwright.config";
import { clearGestures, gestureReport, inTap, installGestureSpy } from "./gesture_spy";

const PAGE = `http://localhost:${PAGE_PORT}`;
const BUS = `http://localhost:${BUS_PORT}/functions/v1/switchboard`;
const CTL = `http://127.0.0.1:${BUS_PORT}`;
const ROOT = join(__dirname, "..");
const SHOTS = process.env.SHOTS_DIR ?? join(ROOT, "test-results", "shots");
mkdirSync(SHOTS, { recursive: true });

async function ctl<T = Record<string, unknown>>(path: string, body: unknown = {}): Promise<T> {
  const r = await fetch(`${CTL}/__test/${path}`, { method: path === "state" ? "GET" : "POST", body: path === "state" ? undefined : JSON.stringify(body) });
  return (await r.json()) as T;
}
interface State { passkeys: number; decisions: { request_id: string; decision: string }[]; devices: Record<string, string>; log: { route: string; status: number; code?: string; body?: Record<string, unknown> }[] }

function url(hash = "", extra = ""): string {
  return `${PAGE}/?bus=${encodeURIComponent(BUS)}${extra}${hash ? `#${hash}` : ""}`;
}

async function authenticator(page: Page, isUserVerified = true): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified, automaticPresenceSimulation: true },
  });
  return { cdp, id: authenticatorId };
}

async function shot(page: Page, name: string) {
  const proj = test.info().project.name;
  await page.screenshot({ path: join(SHOTS, `${proj}-${name}.png`), fullPage: true });
}

async function registerViaPage(page: Page) {
  const { token } = await ctl<{ token: string }>("invite", { name: "iPhone" });
  await page.goto(url(`register=${token}`));
  await page.getByRole("button", { name: "Add passkey" }).click();
  await expect(page.getByText("Passkey added. You can close this page.")).toBeVisible();
}

let dialogs: string[] = [];
test.beforeEach(async ({ page }) => {
  await ctl("reset");
  dialogs = [];
  page.on("dialog", async (d) => { dialogs.push(d.message()); await d.dismiss(); });
  page.on("pageerror", (e) => console.log("pageerror:", e.message));
});

test("register adds a passkey @shots", async ({ page }) => {
  await authenticator(page);
  const { token } = await ctl<{ token: string }>("invite", { name: "iPhone" });
  await page.goto(url(`register=${token}`));
  const btn = page.getByRole("button", { name: "Add passkey" });
  await expect(btn).toBeVisible();
  await shot(page, "register-idle");
  await btn.click();
  await expect(page.getByText("Passkey added. You can close this page.")).toBeVisible();
  await expect(btn).toBeHidden();
  await shot(page, "register-done");
  expect((await ctl<State>("state")).passkeys).toBe(1);
});

test("used invite says the link expired", async ({ page }) => {
  await authenticator(page);
  const { token } = await ctl<{ token: string }>("invite", { name: "iPhone" });
  await page.goto(url(`register=${token}`));
  await page.getByRole("button", { name: "Add passkey" }).click();
  await expect(page.getByText("Passkey added. You can close this page.")).toBeVisible();
  await page.goto(url(`register=${token}`, "&again=1"));
  // Options are fetched on load, so the dead link is reported before any tap.
  await expect(page.getByText("That link expired. Run switchboard passkey add again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeHidden();
  await expect(page.getByRole("button", { name: "Add passkey" })).toBeHidden();
});

test("device code: Confirm signs the Mac in @shots", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { user_code } = await ctl<{ user_code: string }>("device");
  await page.goto(url(`code=${user_code}`));
  await expect(page.getByText(user_code, { exact: true })).toBeVisible();
  await expect(page.getByText("Only confirm if you just ran switchboard login and this code matches.", { exact: true })).toBeVisible();
  await shot(page, "code-idle");
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Signed in on your Mac. You can close this page.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Confirm" })).toBeHidden();
  await shot(page, "code-done");
  const st = await ctl<State>("state");
  expect(st.devices[user_code.replace("-", "")]).toBe("approved");
});

test("device code: Not me blocks the sign-in @shots", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { user_code } = await ctl<{ user_code: string }>("device");
  await page.goto(url(`code=${user_code.toLowerCase()}`));
  await expect(page.getByText(user_code, { exact: true })).toBeVisible(); // shown upper-case
  await page.getByRole("button", { name: "Not me" }).click();
  await expect(page.getByText("Sign-in blocked. You can close this page.")).toBeVisible();
  await shot(page, "code-notme");
  expect((await ctl<State>("state")).devices[user_code.replace("-", "")]).toBe("denied");
});

test("expired code says so, without Retry @shots", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { user_code } = await ctl<{ user_code: string }>("device");
  await ctl("expire_device", { user_code });
  await page.goto(url(`code=${user_code}`));
  // The device options are fetched on load, so the expiry shows before any tap.
  await expect(page.getByText("That code expired. Run switchboard login again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeHidden();
  // Final error: the buttons go away, since pressing them again cannot work.
  await expect(page.getByRole("button", { name: "Confirm" })).toBeHidden();
  await expect(page.getByRole("button", { name: "Not me" })).toBeHidden();
  await shot(page, "code-expired");
});

test("malformed code is refused before any passkey prompt", async ({ page }) => {
  await page.goto(url("code=<b>x</b>"));
  await expect(page.getByText("That code looks wrong. Run switchboard login again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Confirm" })).toHaveCount(0);
  expect(await page.locator("main b").count()).toBe(0);
});

test("list, expand, approve one and deny one @shots", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const five = new Date(Date.now() - 5 * 60_000).toISOString();
  const two = new Date(Date.now() - 2 * 3600_000).toISOString();
  const a = await ctl<{ request_id: string }>("approval", {
    from: "mac.switchboard.s1", created_at: two,
    body: "Deploy switchboard 1.13 to prod?\nIt passes the conformance suite.\nSee https://example.com/run/42",
    context: [{ id: "msg_c1", from: "mac.switchboard.s1", type: "note", created_at: two, body: "Running conformance now." }],
  });
  const b = await ctl<{ request_id: string }>("approval", { from: "ci.bot", created_at: five, body: "Delete the old staging bucket?" });

  await page.goto(url());
  await shot(page, "list-idle");
  await page.getByRole("button", { name: "Show requests" }).click();
  const rowA = page.locator(`[data-request-id="${a.request_id}"]`);
  const rowB = page.locator(`[data-request-id="${b.request_id}"]`);
  await expect(rowA).toContainText("mac.switchboard.s1");
  await expect(rowA).toContainText("Deploy switchboard 1.13 to prod?");
  await expect(rowA).toContainText("2h");
  await expect(rowB).toContainText("ci.bot");
  await expect(rowB).toContainText("5m");
  // Collapsed rows show only the first line.
  await expect(rowA.getByText("It passes the conformance suite.")).toBeHidden();
  await shot(page, "list-collapsed");

  await rowA.getByRole("button", { name: /mac\.switchboard\.s1/ }).click();
  await expect(rowA.getByText("It passes the conformance suite.", { exact: false })).toBeVisible();
  await expect(rowA).toContainText("Running conformance now.");
  await expect(rowA.locator(".first")).toBeHidden(); // summary line not repeated when open
  await expect(rowA).toContainText("https://example.com/run/42");
  expect(await rowA.locator("a").count()).toBe(0); // URL shown as text, not a link
  await shot(page, "list-expanded");

  await rowA.getByRole("button", { name: "Approve" }).click();
  await expect(rowA.getByText("Approved", { exact: true })).toBeVisible();
  await expect(rowA.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);

  await rowB.getByRole("button", { name: /ci\.bot/ }).click();
  await rowB.getByRole("button", { name: "Deny" }).click();
  await expect(rowB.getByText("Denied", { exact: true })).toBeVisible();
  await shot(page, "list-decided");

  const st = await ctl<State>("state");
  expect(st.decisions).toEqual([
    { request_id: a.request_id, decision: "approve" },
    { request_id: b.request_id, decision: "deny" },
  ]);
  // Expanding a row prefetches one options request per decision, each bound to
  // request_id + decision; the decide call then used the matching one.
  const decideOpts = st.log.filter((l) => l.route === "/v1/passkeys/auth/options" && l.body?.purpose === "decide");
  expect(decideOpts.map((l) => [l.body?.request_id, l.body?.decision, l.status])).toEqual([
    [a.request_id, "approve", 200],
    [a.request_id, "deny", 200],
    [b.request_id, "approve", 200],
    [b.request_id, "deny", 200],
  ]);
  expect(st.log.filter((l) => l.route === "/v1/approvals/web/decide").map((l) => l.status)).toEqual([201, 201]);
});

test("empty list says No requests @shots", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  await page.goto(url());
  await page.getByRole("button", { name: "Show requests" }).click();
  await expect(page.getByText("No requests.")).toBeVisible();
  await shot(page, "list-empty");
});

test("cancelled passkey says so, and Retry recovers @shots", async ({ page }) => {
  const auth = await authenticator(page);
  await registerViaPage(page);
  await ctl("approval", { from: "mac.switchboard.s1", body: "Merge the branch?" });
  await auth.cdp.send("WebAuthn.setUserVerified", { authenticatorId: auth.id, isUserVerified: false });
  await page.goto(url());
  await page.getByRole("button", { name: "Show requests" }).click();
  await expect(page.getByText("Passkey cancelled.")).toBeVisible();
  const retry = page.getByRole("button", { name: "Retry" });
  await expect(retry).toBeVisible();
  await shot(page, "error-cancelled");
  await auth.cdp.send("WebAuthn.setUserVerified", { authenticatorId: auth.id, isUserVerified: true });
  await retry.click();
  await expect(page.locator(".first", { hasText: "Merge the branch?" })).toBeVisible();
  await expect(page.getByText("Passkey cancelled.")).toBeHidden();
});

test("network failure says so with Retry", async ({ page }) => {
  await authenticator(page);
  await page.route(`${BUS}/**`, (r) => r.abort("internetdisconnected"));
  const { token } = await ctl<{ token: string }>("invite", {});
  await page.goto(url(`register=${token}`));
  await expect(page.getByText("Network problem. Try again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add passkey" })).toBeDisabled();
  await page.unroute(`${BUS}/**`);
  await page.getByRole("button", { name: "Retry" }).click(); // refetches the options only
  await expect(page.getByText("Network problem. Try again.")).toBeHidden();
  await page.getByRole("button", { name: "Add passkey" }).click();
  await expect(page.getByText("Passkey added. You can close this page.")).toBeVisible();
});

test("XSS probe: agent text renders as text only", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const evil = `Hi <img src=x onerror="window.__xss=1;alert('img')"> <a href="javascript:alert('a')">click</a> javascript:alert('c')`;
  const r = await ctl<{ request_id: string }>("approval", {
    from: `<b onmouseover="alert('from')">bot</b>`, body: evil,
    context: [{ id: "c1", from: "x", type: "note", created_at: new Date().toISOString(), body: `<script>window.__xss=2</script><svg onload="alert('svg')"></svg>` }],
  });
  await page.goto(url());
  await page.getByRole("button", { name: "Show requests" }).click();
  const row = page.locator(`[data-request-id="${r.request_id}"]`);
  await expect(row).toContainText(`<b onmouseover="alert('from')">bot</b>`);
  await row.getByRole("button", { name: /bot/ }).click();
  await expect(row).toContainText(`<img src=x onerror="window.__xss=1;alert('img')">`);
  await expect(row).toContainText(`<a href="javascript:alert('a')">click</a>`);
  await expect(row).toContainText(`<script>window.__xss=2</script>`);
  await page.waitForTimeout(500);
  const injected = await page.evaluate(() => ({
    n: document.querySelectorAll("main img, main a, main script, main svg, main b, main iframe").length,
    xss: (window as unknown as { __xss?: number }).__xss ?? null,
  }));
  expect(injected).toEqual({ n: 0, xss: null });
  expect(dialogs).toEqual([]);
});

test("CSP: shipped file carries the strict policy, and the browser enforces it", async ({ page }) => {
  const html = readFileSync(join(ROOT, "index.html"), "utf8");
  const m = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
  expect(m, "CSP meta tag").not.toBeNull();
  const csp = m![1];
  for (const d of [
    "default-src 'self'", "connect-src https://switchboard.russellzager.com", "img-src 'self' data:",
    "style-src 'self'", "script-src 'self'", "base-uri 'none'", "form-action 'none'",
  ]) expect(csp).toContain(d);
  expect(csp).not.toContain("unsafe-inline");
  expect(csp).not.toContain("unsafe-eval");
  expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/); // no inline scripts
  expect(html).not.toMatch(/\sstyle=/); // no inline styles
  // Positive control that the policy is live: served as shipped (?csp=raw), the page may
  // not reach the local bus, so the fetch is blocked and the user sees a network error.
  await authenticator(page);
  const violations: string[] = [];
  page.on("console", (m) => { if (/Content Security Policy/i.test(m.text())) violations.push(m.text()); });
  const { token } = await ctl<{ token: string }>("invite", {});
  await page.goto(url(`register=${token}`, "&csp=raw"));
  await expect(page.getByText("Network problem. Try again.")).toBeVisible();
  expect(violations.join("\n")).toContain("connect-src");
  expect((await ctl<State>("state")).log.length).toBe(0);
});

test("no dark mode anywhere", async ({ page }) => {
  for (const f of ["index.html", "style.css", "app.js"]) {
    const t = readFileSync(join(ROOT, f), "utf8");
    expect(t, f).not.toMatch(/prefers-color-scheme/i);
    expect(t, f).not.toMatch(/color-scheme\s*:\s*[^;]*dark/i);
    expect(t, f).not.toMatch(/name="color-scheme"[^>]*dark/i);
  }
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(url());
  const dark = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.emulateMedia({ colorScheme: "light" });
  const light = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(dark).toBe(light);
  expect(light).toBe("rgb(255, 255, 255)");
});

test("bus override is honoured on localhost only", async ({ page }) => {
  await page.goto(url());
  const local = await page.evaluate(async () => (await import("/config.js")).BUS_BASE);
  expect(local).toBe(BUS);
  await page.goto(`http://approve.test:${PAGE_PORT}/?bus=${encodeURIComponent("https://evil.example/x")}`);
  const remote = await page.evaluate(async () => (await import("/config.js")).BUS_BASE);
  expect(remote).toBe("https://switchboard.russellzager.com/functions/v1/switchboard");
  // A non-http(s) override is ignored even on localhost.
  await page.goto(`${PAGE}/?bus=${encodeURIComponent("javascript:alert(1)")}`);
  const bad = await page.evaluate(async () => (await import("/config.js")).BUS_BASE);
  expect(bad).toBe("https://switchboard.russellzager.com/functions/v1/switchboard");
});

test("brand and title say Switchboard", async ({ page }) => {
  await page.goto(url());
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Switchboard");
  await expect(page).toHaveTitle("Switchboard");
  await expect(page.locator("body")).not.toContainText(/cutout/i);
});

test("works without the JSON helper APIs (manual base64url fallback)", async ({ page }) => {
  await page.addInitScript(() => {
    const P = PublicKeyCredential as unknown as Record<string, unknown>;
    delete P.parseCreationOptionsFromJSON;
    delete P.parseRequestOptionsFromJSON;
    delete (PublicKeyCredential.prototype as unknown as Record<string, unknown>).toJSON;
    (window as unknown as { __noJsonApi: boolean }).__noJsonApi =
      !("parseCreationOptionsFromJSON" in PublicKeyCredential) && !("toJSON" in PublicKeyCredential.prototype);
  });
  await authenticator(page);
  await registerViaPage(page);
  expect(await page.evaluate(() => (window as unknown as { __noJsonApi: boolean }).__noJsonApi)).toBe(true);
  const { user_code } = await ctl<{ user_code: string }>("device");
  await page.goto(url(`code=${user_code}`));
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Signed in on your Mac. You can close this page.")).toBeVisible();
});

test("refuses to run inside a frame", async ({ page }) => {
  await page.goto(`http://127.0.0.1:${PAGE_PORT}/style.css`);
  await page.setContent(`<iframe src="${url()}" width="400" height="300"></iframe>`);
  const frame = page.frameLocator("iframe");
  await expect(frame.getByText("Open this page directly.")).toBeVisible();
  await expect(frame.getByRole("button", { name: "Show requests" })).toHaveCount(0);
});

test("every passkey prompt starts inside the tap, with no fetch before it", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  expect(await gestureReport(page)).toEqual([inTap("create")]);
  await clearGestures(page);

  const { user_code } = await ctl<{ user_code: string }>("device");
  await page.goto(url(`code=${user_code}`));
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Signed in on your Mac. You can close this page.")).toBeVisible();
  expect(await gestureReport(page)).toEqual([inTap("get")]);
  await clearGestures(page);

  const a = await ctl<{ request_id: string }>("approval", { body: "First?" });
  const b = await ctl<{ request_id: string }>("approval", { body: "Second?" });
  await page.goto(url());
  await page.getByRole("button", { name: "Show requests" }).click();
  const rowA = page.locator(`[data-request-id="${a.request_id}"]`);
  const rowB = page.locator(`[data-request-id="${b.request_id}"]`);
  await rowA.locator("button.row").click();
  await rowA.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(rowA.getByText("Approved", { exact: true })).toBeVisible();
  await rowB.locator("button.row").click();
  await rowB.getByRole("button", { name: "Deny", exact: true }).click();
  await expect(rowB.getByText("Denied", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("No requests.")).toBeVisible();
  expect(await gestureReport(page)).toEqual([inTap("get"), inTap("get"), inTap("get"), inTap("get")]);
  expect((await ctl<State>("state")).decisions.map((d) => d.decision)).toEqual(["approve", "deny"]);
});

test("stale prefetched challenge: refetch, ask for one more tap, never loop", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  await clearGestures(page);
  const { user_code } = await ctl<{ user_code: string }>("device");
  await page.clock.install();
  await page.goto(url(`code=${user_code}`));
  await expect(page.getByRole("button", { name: "Confirm" })).toBeEnabled();
  await page.clock.fastForward("04:10"); // past the 240 s freshness limit
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("That took too long. Try again.")).toBeVisible();
  expect(await gestureReport(page)).toEqual([]); // no passkey prompt with the stale challenge
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("Signed in on your Mac. You can close this page.")).toBeVisible();
  expect(await gestureReport(page)).toEqual([inTap("get")]);
  const opts = (await ctl<State>("state")).log.filter((l) => l.route === "/v1/passkeys/auth/options" && l.body?.purpose === "device");
  expect(opts.length).toBe(2);
});

test("bad_challenge after the prompt: refetch and Retry, one prompt per tap", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  await ctl("approval", { body: "Ship it?" });
  await page.goto(url());
  await clearGestures(page);
  await ctl("fail_next", { code: "bad_challenge" });
  await page.getByRole("button", { name: "Show requests" }).click();
  await expect(page.getByText("That took too long. Try again.")).toBeVisible();
  await page.waitForTimeout(500);
  expect(await gestureReport(page)).toEqual([inTap("get")]); // no automatic second prompt
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.locator(".first", { hasText: "Ship it?" })).toBeVisible();
  expect(await gestureReport(page)).toEqual([inTap("get"), inTap("get")]);
});

test("bad_assertion offers Retry, and Retry recovers", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  await ctl("approval", { body: "Rotate the key?" });
  await page.goto(url());
  await ctl("fail_next", { code: "bad_assertion" });
  await page.getByRole("button", { name: "Show requests" }).click();
  await expect(page.getByText("Passkey not recognized. Try again, or run switchboard passkey add.")).toBeVisible();
  const retry = page.getByRole("button", { name: "Retry" });
  await expect(retry).toBeVisible();
  await retry.click();
  await expect(page.locator(".first", { hasText: "Rotate the key?" })).toBeVisible();
});

test("register Retry fetches new options after a failed create()", async ({ page }) => {
  const auth = await authenticator(page);
  await auth.cdp.send("WebAuthn.setUserVerified", { authenticatorId: auth.id, isUserVerified: false });
  const { token } = await ctl<{ token: string }>("invite", { name: "iPhone" });
  await page.goto(url(`register=${token}`));
  await page.getByRole("button", { name: "Add passkey" }).click();
  await expect(page.getByText("Passkey cancelled.")).toBeVisible();
  await auth.cdp.send("WebAuthn.setUserVerified", { authenticatorId: auth.id, isUserVerified: true });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("Passkey added. You can close this page.")).toBeVisible();
  const st = await ctl<State>("state");
  expect(st.log.filter((l) => l.route === "/v1/passkeys/register/options").map((l) => l.status)).toEqual([200, 200]);
  expect(st.log.filter((l) => l.route === "/v1/passkeys/register/verify").map((l) => l.status)).toEqual([201]);
});

test("root page: Have a code? opens the code screen @shots", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { user_code } = await ctl<{ user_code: string }>("device");
  await page.goto(url());
  const input = page.getByLabel("Have a code?");
  await expect(input).toBeVisible();
  await shot(page, "root");
  await input.fill("bcdf");
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await expect(page.getByText("That code looks wrong.", { exact: true })).toBeVisible();
  await input.fill(user_code.replace("-", "").toLowerCase()); // any case, no dash
  await input.press("Enter");
  await expect(page.getByText(user_code, { exact: true })).toBeVisible();
  await expect(page.getByText("Only confirm if you just ran switchboard login and this code matches.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Signed in on your Mac. You can close this page.")).toBeVisible();
  expect((await ctl<State>("state")).devices[user_code.replace("-", "")]).toBe("approved");
});

test("text cut at the bus cap is marked (shortened)", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const cap = "Long plan:\n" + "é".repeat(1989); // 2000 code points: what the bus cut
  const long = await ctl<{ request_id: string }>("approval", {
    body: cap,
    context: [{ id: "c1", from: "x", type: "note", created_at: new Date().toISOString(), body: "y".repeat(2000) }],
  });
  const short = await ctl<{ request_id: string }>("approval", { body: "x".repeat(1999) });
  await page.goto(url());
  await page.getByRole("button", { name: "Show requests" }).click();
  const rowL = page.locator(`[data-request-id="${long.request_id}"]`);
  const rowS = page.locator(`[data-request-id="${short.request_id}"]`);
  await rowL.locator("button.row").click();
  await rowS.locator("button.row").click();
  await expect(rowL.locator(".detail .shortened")).toHaveCount(2); // body and context
  await expect(rowL.locator(".detail .shortened").first()).toHaveText("(shortened)");
  await expect(rowS.locator(".detail .shortened")).toHaveCount(0);
});


// ------------------------------------------------------------------ enrollments
interface EState extends State { enrollments: Record<string, string>; enroll_requests: Record<string, unknown>[] }
const enrollOpts = (st: State) => st.log.filter((l) => l.route === "/v1/passkeys/auth/options" && l.body?.purpose === "enroll_decide")
  .map((l) => [l.body?.enrollment_id, l.body?.decision, l.status]);

async function showEnrollment(page: Page, enrollment_id: string) {
  await page.goto(url(`enroll=${enrollment_id}`));
  await page.getByRole("button", { name: "Show request" }).click();
  await expect(page.locator(".enroll-id")).toBeVisible();
}

test("enroll link: lookalike needs the extra confirm; wrong codes count down to denied @shots", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", {
    requested_id: "muse", platform: "meta-muse", display_name: "Muse", requested_by: null,
    lookalike_of: ["muse-1", "muse2"], code: "4829",
  });
  await clearGestures(page);
  await showEnrollment(page, enrollment_id);
  const main = page.locator("main");
  await expect(page.locator(".enroll-id")).toHaveText("muse");
  await expect(main).toContainText("meta-muse");
  await expect(main).toContainText("Muse");
  await expect(main).toContainText("the full window");
  await expect(main).toContainText(/Expires\s*in \d+ min/);
  await expect(page.getByRole("note")).toContainText("muse looks like muse-1, muse2.");
  const approve = page.getByRole("button", { name: "Approve", exact: true });
  const deny = page.getByRole("button", { name: "Deny", exact: true });
  const code = page.getByLabel("Code the agent shows");
  const confirm = page.getByLabel("I checked: this is the agent I expect.");
  await expect(deny).toBeEnabled(); // decide challenges are prefetched
  await code.fill("1111");
  await expect(approve).toBeDisabled(); // a similar ID needs the extra confirm first
  await confirm.check();
  await expect(approve).toBeEnabled();
  await shot(page, "enroll-lookalike");

  await approve.click();
  await expect(page.getByText("Wrong code. 2 tries left.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeHidden(); // fix the code, tap Approve again
  await expect(code).toHaveValue("");
  await expect(approve).toBeDisabled(); // until a code is typed again
  await expect(page.locator(".fields dd").last()).toHaveText("2");
  await shot(page, "enroll-wrong-code");

  await code.fill("2222");
  await expect(approve).toBeEnabled(); // a fresh challenge was fetched for this tap
  await approve.click();
  await expect(page.getByText("Wrong code. 1 try left.", { exact: true })).toBeVisible();
  await code.fill("3333");
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect(page.getByRole("status")).toHaveText("Denied after 3 wrong codes.");
  await expect(approve).toHaveCount(0);
  await expect(deny).toHaveCount(0);
  await expect(code).toHaveCount(0);
  await shot(page, "enroll-denied");

  const st = await ctl<EState>("state");
  expect(st.enrollments[enrollment_id]).toBe("denied");
  // One fresh approve challenge per tap (Safari: no fetch between the tap and the prompt).
  expect(enrollOpts(st)).toEqual([
    [enrollment_id, "approve", 200], [enrollment_id, "deny", 200],
    [enrollment_id, "approve", 200], [enrollment_id, "approve", 200],
  ]);
  expect(st.log.filter((l) => l.route === "/v1/enrollments/web/decide").map((l) => [l.status, l.code]))
    .toEqual([[409, "code_mismatch"], [409, "code_mismatch"], [409, "code_mismatch"]]);
  expect(await gestureReport(page)).toEqual([inTap("get"), inTap("get"), inTap("get"), inTap("get")]);
});

test("enroll link: right code (spaces stripped) approves; reply-only key stored", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "scout", reply_token: true, code: "482913" });
  await clearGestures(page);
  await showEnrollment(page, enrollment_id);
  await expect(page.getByRole("note")).toHaveCount(0); // no lookalike, no extra confirm
  await expect(page.locator("main")).toContainText("rz-operator.s1");
  const approve = page.getByRole("button", { name: "Approve", exact: true });
  await page.getByLabel("Code the agent shows").fill("48 291"); // 5 digits
  await expect(approve).toBeDisabled(); // 4 or 6 digits only
  await page.getByLabel("Code the agent shows").fill("482 913");
  await approve.click();
  await expect(page.getByRole("status")).toHaveText("Approved scout. Reply-only key stored.");
  const st = await ctl<EState>("state");
  expect(st.enrollments[enrollment_id]).toBe("approved");
  expect(st.enroll_requests).toEqual([{ enrollment_id, decision: "approve", code: "482913", replace: false }]);
  expect(await gestureReport(page)).toEqual([inTap("get"), inTap("get")]);
});

test("enroll link: replace warning shows, and replace is sent", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "muse", replace: true });
  await showEnrollment(page, enrollment_id);
  await expect(page.getByText("This replaces the existing agent muse; its old key stops working.", { exact: true })).toBeVisible();
  await shot(page, "enroll-replace");
  await page.getByLabel("Code the agent shows").fill("4829");
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Approved muse.");
  expect((await ctl<EState>("state")).enroll_requests).toEqual([{ enrollment_id, decision: "approve", code: "4829", replace: true }]);
});

test("enroll link: Deny sends no code", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", { lookalike_of: ["muse-1"] });
  await clearGestures(page);
  await showEnrollment(page, enrollment_id);
  await page.getByLabel("Code the agent shows").fill("1234"); // typed, but Deny must not send it
  await page.getByRole("button", { name: "Deny", exact: true }).click(); // no confirm needed to deny
  await expect(page.getByRole("status")).toHaveText("Denied.");
  const st = await ctl<EState>("state");
  expect(st.enrollments[enrollment_id]).toBe("denied");
  expect(st.enroll_requests).toEqual([{ enrollment_id, decision: "deny" }]);
  expect(await gestureReport(page)).toEqual([inTap("get"), inTap("get")]);
});

test("enroll link: decided elsewhere, or absent, says No longer pending", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", {});
  await showEnrollment(page, enrollment_id);
  await ctl("enrollment_status", { enrollment_id, status: "approved" }); // e.g. approved from the CLI
  await page.getByLabel("Code the agent shows").fill("4829");
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("No longer pending.");
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
  // A link to a row that is no longer listed.
  await page.goto(url(`enroll=${enrollment_id}`, "&again=1"));
  await page.getByRole("button", { name: "Show request" }).click();
  await expect(page.getByRole("status")).toHaveText("No longer pending.");
  await expect(page.getByLabel("Code the agent shows")).toHaveCount(0);
});

test("enroll link: id_contested says deny and enroll again, and keeps Deny", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", {});
  await showEnrollment(page, enrollment_id);
  await ctl("enroll_fail_next", { code: "id_contested" });
  const approve = page.getByRole("button", { name: "Approve", exact: true });
  await page.getByLabel("Code the agent shows").fill("4829");
  await approve.click();
  await expect(page.getByText("Two requests ask for this ID, and one may not be your agent. Deny, then ask your agent to enroll again.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeHidden();
  const deny = page.getByRole("button", { name: "Deny", exact: true });
  await expect(deny).toBeEnabled(); // with a fresh challenge
  await deny.click();
  await expect(page.getByRole("status")).toHaveText("Denied.");
});

test("enroll link: already_registered is final, with plain words", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", {});
  await showEnrollment(page, enrollment_id);
  await ctl("enroll_fail_next", { code: "already_registered" });
  await page.getByLabel("Code the agent shows").fill("4829");
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByText("That ID is already taken. Ask the agent to enroll again.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeHidden();
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeHidden();
  await expect(page.getByRole("button", { name: "Deny", exact: true })).toBeHidden();
});

test("malformed enroll link is refused before any passkey prompt", async ({ page }) => {
  await installGestureSpy(page);
  await page.goto(url("enroll=<b>x</b>"));
  await expect(page.getByText("That link looks wrong.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Show request" })).toHaveCount(0);
  expect(await page.locator("main b").count()).toBe(0);
  expect(await gestureReport(page)).toEqual([]);
  expect((await ctl<State>("state")).log.length).toBe(0);
});

test("root page: Enrollments list next to the requests @shots", async ({ page }) => {
  await installGestureSpy(page);
  await authenticator(page);
  await registerViaPage(page);
  const old = new Date(Date.now() - 3 * 60_000).toISOString();
  const a = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "muse", lookalike_of: ["muse-1"], created_at: old });
  const b = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "scout", display_name: "Scout", platform: "cli", replace: true });
  await clearGestures(page);
  await page.goto(url());
  await expect(page.getByRole("heading", { name: "Enrollments" })).toBeVisible();
  await page.getByRole("button", { name: "Show enrollments" }).click();
  const rowA = page.locator(`[data-enrollment-id="${a.enrollment_id}"]`);
  const rowB = page.locator(`[data-enrollment-id="${b.enrollment_id}"]`);
  await expect(rowA).toContainText("muse");
  await expect(rowA).toContainText("similar ID");
  await expect(rowA).toContainText("3m");
  await expect(rowB).toContainText("Scout · cli");
  await expect(rowB).toContainText("replaces");
  await expect(page.locator("[data-enrollment-id] .row").first()).toContainText("muse"); // oldest first
  await shot(page, "enroll-list");
  await rowB.locator("button.row").click();
  await expect(rowB.getByText("This replaces the existing agent scout; its old key stops working.", { exact: true })).toBeVisible();
  await rowB.getByLabel("Code the agent shows").fill("4829");
  await rowB.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(rowB.locator(".badge")).toHaveText("Approved");
  await expect(rowB.getByRole("status")).toHaveText("Approved scout.");
  await rowA.locator("button.row").click();
  await rowA.getByRole("button", { name: "Deny", exact: true }).click();
  await expect(rowA.locator(".badge")).toHaveText("Denied");
  await shot(page, "enroll-list-decided");
  const st = await ctl<EState>("state");
  expect(st.enrollments).toEqual({ [a.enrollment_id]: "denied", [b.enrollment_id]: "approved" });
  expect(await gestureReport(page)).toEqual([inTap("get"), inTap("get"), inTap("get")]);
});

test("XSS probe: enrollment fields render as text only", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", {
    requested_id: `<b onmouseover="alert('id')">x</b>`,
    platform: `<img src=x onerror="window.__xss=1">`,
    display_name: `<script>window.__xss=2</script>`,
    requested_by: `<svg onload="window.__xss=3"></svg>`,
    lookalike_of: [`<iframe src="javascript:window.__xss=4"></iframe>`],
    replace: true,
  });
  await showEnrollment(page, enrollment_id);
  const main = page.locator("main");
  await expect(main).toContainText(`<img src=x onerror="window.__xss=1">`);
  await expect(main).toContainText(`<script>window.__xss=2</script>`);
  await expect(main).toContainText(`<svg onload="window.__xss=3"></svg>`);
  await expect(main).toContainText(`<iframe src="javascript:window.__xss=4"></iframe>`);
  await expect(main).toContainText(`This replaces the existing agent <b onmouseover="alert('id')">x</b>; its old key stops working.`);
  await page.waitForTimeout(500);
  const injected = await page.evaluate(() => ({
    n: document.querySelectorAll("main img, main a, main script, main svg, main b, main iframe").length,
    xss: (window as unknown as { __xss?: number }).__xss ?? null,
  }));
  expect(injected).toEqual({ n: 0, xss: null });
  expect(dialogs).toEqual([]);
});

// Holds the next passkey result until window.__release() is called. The prompt itself
// still runs inside the tap; only the page's view of the result is delayed.
async function holdNextPrompt(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __release?: () => void };
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (o?: CredentialRequestOptions) =>
      orig(o).then((c) => new Promise<Credential | null>((r) => { w.__release = () => r(c); }));
  });
}
async function releasePrompt(page: Page) {
  await page.waitForFunction(() => typeof (window as unknown as { __release?: () => void }).__release === "function");
  await page.evaluate(() => (window as unknown as { __release: () => void }).__release());
}

test("enroll link: malformed ID offers only Deny", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const bad = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "mu\u202ese", lookalike_of: ["muse-1"] });
  const badLook = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "scout", lookalike_of: ["Scout"] });
  const fine = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "muse-2", lookalike_of: ["muse-1"] });
  await showEnrollment(page, bad.enrollment_id);
  await expect(page.getByText("This request looks malformed. Deny it.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Code the agent shows")).toHaveCount(0);
  await expect(page.getByLabel("I checked: this is the agent I expect.")).toHaveCount(0);
  await page.getByRole("button", { name: "Deny", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Denied.");
  // The list flags a bad lookalike_of entry too; a well-formed row is not flagged.
  await page.goto(url());
  await page.getByRole("button", { name: "Show enrollments" }).click();
  const rowL = page.locator(`[data-enrollment-id="${badLook.enrollment_id}"]`);
  const rowF = page.locator(`[data-enrollment-id="${fine.enrollment_id}"]`);
  await expect(rowL.locator(".flag", { hasText: "malformed" })).toHaveCount(1);
  await expect(rowF.locator(".flag", { hasText: "malformed" })).toHaveCount(0);
  await rowL.locator("button.row").click();
  await expect(rowL.getByText("This request looks malformed. Deny it.", { exact: true })).toBeVisible();
  await expect(rowL.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
  await rowF.locator("button.row").click();
  await expect(rowF.getByRole("button", { name: "Approve", exact: true })).toHaveCount(1);
  expect((await ctl<EState>("state")).enroll_requests).toEqual([{ enrollment_id: bad.enrollment_id, decision: "deny" }]);
});

test("enroll: IDs are bidi-isolated and lookalike IDs are monospace", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "muse", display_name: "Muse", lookalike_of: ["muse-1", "muse2"] });
  await showEnrollment(page, enrollment_id);
  const style = (sel: string) => page.locator(sel).first().evaluate((el) => {
    const s = getComputedStyle(el);
    return { bidi: s.unicodeBidi, mono: /monospace/.test(s.fontFamily) };
  });
  expect(await style(".enroll-id")).toEqual({ bidi: "isolate", mono: true });
  expect((await style(".fields dd")).bidi).toBe("isolate");
  await expect(page.locator(".alert .id")).toHaveText(["muse", "muse-1", "muse2"]);
  expect(await style(".alert .id")).toEqual({ bidi: "isolate", mono: true });
  await page.goto(url());
  await page.getByRole("button", { name: "Show enrollments" }).click();
  expect((await style("[data-enrollment-id] .from")).bidi).toBe("isolate");
  expect((await style("[data-enrollment-id] .first")).bidi).toBe("isolate");
});

test("enroll link: code and confirm are read at the tap; inputs lock while busy", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "muse", lookalike_of: ["muse-1"], code: "4829" });
  await showEnrollment(page, enrollment_id);
  const code = page.getByLabel("Code the agent shows");
  const confirm = page.getByLabel("I checked: this is the agent I expect.");
  await code.fill("4829");
  await confirm.check();
  await holdNextPrompt(page);
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(code).toBeDisabled();
  await expect(confirm).toBeDisabled();
  // A script (not the owner) edits both while the prompt is open; what was tapped is what is sent.
  await page.evaluate(() => {
    const c = document.querySelector<HTMLInputElement>(".code-entry input")!;
    c.value = "1111"; c.dispatchEvent(new Event("input"));
    const b = document.querySelector<HTMLInputElement>(".confirm input")!;
    b.checked = false; b.dispatchEvent(new Event("change"));
  });
  await releasePrompt(page);
  await expect(page.getByRole("status")).toHaveText("Approved muse.");
  await expect(confirm).toBeDisabled();
  expect((await ctl<EState>("state")).enroll_requests).toEqual([{ enrollment_id, decision: "approve", code: "4829", replace: false }]);
});

test("enroll link: a decide that ends after the view is gone still shows its result", async ({ page }) => {
  await authenticator(page);
  await registerViaPage(page);
  const { enrollment_id } = await ctl<{ enrollment_id: string }>("enrollment", { requested_id: "scout", code: "4829" });
  await showEnrollment(page, enrollment_id);
  await page.getByLabel("Code the agent shows").fill("4829");
  await holdNextPrompt(page);
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await page.waitForFunction(() => typeof (window as unknown as { __release?: () => void }).__release === "function");
  await page.evaluate(() => { location.hash = ""; }); // the root page replaces the view
  await expect(page.getByRole("button", { name: "Show enrollments" })).toBeVisible();
  await releasePrompt(page);
  await expect(page.getByRole("status")).toHaveText("scout: Approved scout.");
  expect(await page.locator(".result .id").evaluate((el) => getComputedStyle(el).unicodeBidi)).toBe("isolate");
  expect((await ctl<EState>("state")).enrollments[enrollment_id]).toBe("approved");
});
