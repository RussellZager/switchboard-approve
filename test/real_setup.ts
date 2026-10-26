// Global setup for E2E_TARGET=real: start the real local Switchboard bus and the page server.
//
// 1. `python3 tests/run_local_bus.py --passkeys-origin http://localhost:18765 --port <BUS_PORT>`
//    in the bus repo (SWITCHBOARD_REPO, then CUTOUT_REPO). It prints one JSON line (base_url, keys, ids).
// 2. test/serve_page.ts on exactly http://localhost:18765, with CSP connect-src = the bus origin.
// Both stop with SIGTERM in the returned teardown (never SIGKILL: the bus deletes its
// scratch Postgres cluster on SIGTERM).
import { spawn, type ChildProcess } from "node:child_process";
import { createWriteStream, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const ROOT = join(__dirname, "..");
// The bus's PASSKEY_ORIGIN is set to exactly http://localhost:<REAL_PAGE_PORT> (default 18765).
// Override with REAL_PAGE_PORT when another process (e.g. gnubby-ssh) holds 18765.
export const REAL_PAGE_PORT = Number(process.env.REAL_PAGE_PORT ?? 18765);
export const REAL_BUS_PORT = Number(process.env.REAL_BUS_PORT ?? 18766);
export const LB_FILE = join(ROOT, "test-results", "real-bus.json");
// The bus checkout folder was renamed cutout -> bus (design §2, U15).
const BUS_REPO = process.env.SWITCHBOARD_REPO || process.env.CUTOUT_REPO || "/Users/rzager/Code/rz@russellzager.com/switchboard/bus";

function waitForLine(p: ChildProcess, match: (line: string) => boolean, what: string, ms: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error(`${what}: no ready line after ${ms} ms`)), ms);
    p.stdout!.on("data", (d: Buffer) => {
      buf += d.toString();
      for (const line of buf.split("\n")) {
        if (match(line)) { clearTimeout(timer); resolve(line); return; }
      }
    });
    p.on("exit", (code) => { clearTimeout(timer); reject(new Error(`${what} exited early (code ${code})`)); });
  });
}

function stop(p: ChildProcess, what: string, ms = 90_000): Promise<void> {
  return new Promise((resolve) => {
    if (p.exitCode !== null || p.signalCode !== null) { resolve(); return; }
    const timer = setTimeout(() => {
      console.warn(`[real] ${what} (pid ${p.pid}) did not exit ${ms} ms after SIGTERM; left running, not SIGKILLed`);
      resolve();
    }, ms);
    p.once("exit", (code, sig) => { clearTimeout(timer); console.log(`[real] ${what} stopped (code ${code}, signal ${sig})`); resolve(); });
    p.kill("SIGTERM");
  });
}

export default async function globalSetup() {
  mkdirSync(join(ROOT, "test-results"), { recursive: true });
  const busLog = createWriteStream(join(ROOT, "test-results", "real-bus.stderr.log"));
  const bus = spawn("python3", [
    "tests/run_local_bus.py", "--passkeys-origin", `http://localhost:${REAL_PAGE_PORT}`, "--port", String(REAL_BUS_PORT),
  ], { cwd: BUS_REPO, stdio: ["ignore", "pipe", "pipe"] });
  bus.stderr!.pipe(busLog);
  let page: ChildProcess | null = null;
  const teardown = async () => {
    if (page) await stop(page, "page server", 10_000);
    await stop(bus, "local bus");
  };
  try {
    const line = await waitForLine(bus, (l) => l.trim().startsWith("{") && l.includes("base_url"), "local bus", 240_000);
    const lb = JSON.parse(line.trim());
    if (lb.origin !== `http://localhost:${REAL_PAGE_PORT}` || lb.rp_id !== "localhost") {
      throw new Error(`bus origin/rp_id mismatch: ${lb.origin} ${lb.rp_id}`);
    }
    writeFileSync(LB_FILE, JSON.stringify(lb));
    const connect = new URL(lb.base_url).origin;
    page = spawn("deno", ["run", "--config", "test/deno.json", "--allow-net", "--allow-read", "--allow-env", "test/serve_page.ts"], {
      cwd: ROOT, stdio: ["ignore", "pipe", "inherit"],
      env: { ...process.env, PAGE_PORT: String(REAL_PAGE_PORT), CONNECT_ORIGIN: connect },
    });
    await waitForLine(page, (l) => l.startsWith("page http://localhost:"), "page server", 60_000);
    console.log(`[real] bus ${lb.base_url} (pid ${bus.pid}); page http://localhost:${REAL_PAGE_PORT} connect-src ${connect}`);
  } catch (e) {
    await teardown();
    throw e;
  }
  return teardown;
}
