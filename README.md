# switchboard-approve

The static page at `https://approve.russellzager.com` for [Switchboard](../bus) passkeys.
It does four things, chosen by the URL fragment:

| URL | What the owner sees |
|---|---|
| `#register=<token>` (from `switchboard passkey add`) | **Add passkey** → "Passkey added. You can close this page." |
| `#code=WDJB-MJHT` (from `switchboard login`) | The code, **Confirm** / **Not me** → "Signed in on your Mac." |
| no fragment | **Show requests** → one line per pending agent request; tap for full text; **Approve** / **Deny**. **Show enrollments** → one line per pending agent enrollment; tap for the same view as `#enroll=` |
| `#enroll=enr_…` (an agent asking to join) | **Show request** → the agent's ID, kind, platform, name, who asked (or "the full window"), expiry and code tries left; a warning when the ID looks like another agent's (Approve needs an extra check) or replaces one; type the code the agent shows → **Approve** / **Deny**. The page never receives the code. The code and the extra check are read at the tap, and both inputs lock while the passkey prompt runs. A row whose ID (or a similar-ID entry) is not lower-case words joined by `-` says "This request looks malformed. Deny it." and offers only **Deny**. A result that arrives after the view was replaced still shows on the page. |

Every action asks for the passkey again (Face ID / Touch ID). Each bus challenge is single use and bound to that one action: the invite, the login code, the list, one `request_id` + decision, the enrollment list, or one `enrollment_id` + decision. The page stores nothing: no cookies, no localStorage, no session.

The browser API it calls is the Switchboard SPEC (v1.12+) section "Passkeys and phone approvals"; the bus is the WebAuthn verifier.

## Files

| File | Purpose |
|---|---|
| `index.html` | Shell plus the CSP meta tag |
| `app.js` | All logic (ES module, no framework, no build step, no third-party code) |
| `style.css` | Light-only, mobile-first styles (there is no dark theme) |
| `config.js` | Bus base URL; a `?bus=` override works only on `localhost` / `127.0.0.1` |
| `CNAME` | GitHub Pages custom domain |
| `.nojekyll` | Serve files as-is |
| `test/` | Fake bus and Playwright tests (not used by the site) |

## Security notes

- Agent-written text is untrusted. `app.js` puts it in the DOM only as text nodes (`textContent`), so markup shows literally and URLs are never clickable. The code never uses `innerHTML`.
- CSP (meta tag): `default-src 'self'; connect-src <bus origin>; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'`. No inline scripts or styles.
- `frame-ancestors` cannot be set from a meta tag, and GitHub Pages cannot send response headers. So `app.js` refuses to run inside any frame ("Open this page directly.").
- The page has no secrets. The bus allows CORS only from this page's origin.
- **The RP ID is permanent.** Passkeys are bound to `approve.russellzager.com`. Moving the page to another host means registering new passkeys.

## Passkey prompts and Safari

Safari can refuse `navigator.credentials.*` when an awaited fetch runs between the tap and the call. So the page fetches each challenge **before** the tap: register and device-code options on load, list options on load (and again after each list), and both decide options when a row is expanded. Enrollments work the same way: `enroll_list` options on load, and both `enroll_decide` options when a row opens. A wrong enrollment code uses up its challenge, so the page fetches a new one before Approve works again. A tap starts the passkey prompt synchronously. Buttons stay disabled until their options arrive.

- Challenges live 300 s. A prefetched challenge older than 240 s is not used: the page fetches a new one and shows "That took too long. Try again." with Retry. `bad_challenge` from the bus does the same.
- Every Retry after a failed prompt or a failed check uses a new challenge. The page never retries on its own.
- `test/gesture_spy.ts` logs clicks, fetches, and passkey calls in the page. Both suites assert that every prompt started inside its tap with no fetch first.

Other screens: the code screen says "Only confirm if you just ran switchboard login and this code matches." The root page has a "Have a code?" box (any case, dash optional) for when the CLI cannot open the browser. Text the bus cut at 2000 characters ends with "(shortened)".

## Changing the bus URL

Edit `DEFAULT_BUS_BASE` in `config.js` **and** the `connect-src` origin in `index.html`. They must match, or the CSP blocks every request (the page then says "Network problem.").

## Deploy (GitHub Pages, custom domain)

Live at `https://approve.russellzager.com`. The GitHub repo keeps the name `cutout-approve` until the repo rename (design §2); first-time setup was:

```sh
gh repo create RussellZager/cutout-approve --public --source . --push
gh api -X POST repos/RussellZager/cutout-approve/pages -f 'source[branch]=main' -f 'source[path]=/'
gh api -X PUT repos/RussellZager/cutout-approve/pages -f cname=approve.russellzager.com
```

1. In Squarespace DNS add a CNAME record: host `approve`, data `russellzager.github.io`.
2. Wait for the certificate: `gh api repos/RussellZager/cutout-approve/pages --jq .https_certificate.state` must say `approved`.
3. Then enforce HTTPS: `gh api -X PUT repos/RussellZager/cutout-approve/pages -F https_enforced=true`.
4. Check: `curl -sI https://approve.russellzager.com/ | head -1` gives `200`.
5. On the bus, set `PASSKEY_RP_ID=approve.russellzager.com` and `PASSKEY_ORIGIN=https://approve.russellzager.com`.

## Test

Needs `deno` and `bun`. Playwright uses its own Chromium (`bunx playwright install chromium` if missing), never your normal browser profile.

```sh
bun install
bunx playwright test            # phone viewport: every test; desktop viewport: screenshot tests
test/mutation.sh                # breaks escaping, bindings, frame guard, final errors, tap-to-prompt, stale/reused challenges, Retry, (shortened), warning, code box, and the enrollment view (lookalike confirm, replace warning, tries left, third wrong code, text-only fields, binding, digits-only code, Deny without code, code gate, fresh challenge after a wrong code, malformed ID, monospace lookalike IDs, code and confirm read at the tap, inputs locked while busy, result kept after the view is gone); each named test must go red
SHOTS_DIR=/tmp/shots bunx playwright test   # where screenshots go (default test-results/shots)
PAGE_PORT=18865 BUS_PORT=18866 bunx playwright test   # fake target on other ports (gnubby-ssh can hold 18765)
```

- `test/fake_bus.ts` implements the browser routes of the bus with real WebAuthn verification (`@simplewebauthn/server`), the contract's CORS rules, and single-use bound challenges. It also serves the page on a second port, so page and bus are cross-origin. RP ID is `localhost`.
- The fake page server rewrites the CSP `connect-src` to the fake bus. `?csp=raw` serves the file as shipped; one test uses it to prove the browser enforces the CSP.
- `test/e2e.pw.ts` drives the page with Chrome's CDP virtual authenticator (CTAP2, internal, resident key, user verification). It covers register, login Confirm / Not me, list + approve + deny, expired code, cancelled passkey, network failure, an XSS probe, CSP, no dark mode, the localhost-only override, the manual base64url fallback, frame refusal, prompts inside the tap, stale and bad challenges, bad_assertion Retry, register Retry with new options, the "Have a code?" box, the "(shortened)" marker, and enrollments (`#enroll=` and the root list: lookalike confirm, wrong codes down to denied, replace, Deny, gone rows, id_contested, already_registered, an XSS probe, a malformed ID, bidi isolation and monospace IDs, code and confirm read at the tap, a result after the view is gone). `/__test/fail_next` makes the next assertion check fail with a chosen code. `/__test/enrollment` seeds a pending enrollment (its code stays in the fake bus), `/__test/enrollment_status` decides one behind the page's back, and `/__test/enroll_fail_next` makes the next correct-code approve fail with a chosen 409 code.

### Real local bus

```sh
E2E_TARGET=real bunx playwright test         # project real-phone: test/real.pw.ts only
MUT_TARGET=real test/mutation.sh             # real-bus mutation arms; each must go red
SWITCHBOARD_REPO=/path/to/bus E2E_TARGET=real bunx playwright test   # default: the usual bus checkout (CUTOUT_REPO still read)
```

- `test/real_setup.ts` (globalSetup) starts `python3 tests/run_local_bus.py --passkeys-origin http://localhost:18765 --port 18766` in `SWITCHBOARD_REPO`, then serves the page on **exactly `http://localhost:18765`** (the bus CORS and passkey origin are exact-match). Ports 18765 and 18766 must be free; override them with `REAL_PAGE_PORT` and `REAL_BUS_PORT` (e.g. `REAL_PAGE_PORT=28765 REAL_BUS_PORT=28766 E2E_TARGET=real bunx playwright test`). Teardown sends SIGTERM only. Bus stderr goes to `test-results/real-bus.stderr.log`.
- `test/real.pw.ts` seeds only through the bus API (TypeScript ports of the invite / device / poll / ask / thread recipes), never through test-only routes. It checks that the CLI poll gets the token after Confirm and `access_denied` after Not me, and that the requester's thread shows each approve / deny with `verified_sender_role: operator`, and that a second decision gets "Already decided".
- `test/serve_page.ts` is the shared page server (CSP `connect-src` rewrite, `?csp=raw`), used by both targets.
- GitHub Pages also publishes `test/`, `package.json` and this README. They hold no secrets.
