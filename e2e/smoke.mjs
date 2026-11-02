// End-to-end test of the UI against the Linux local backend: a real relay, the Vite dev server,
// a compiled target process and Chromium. Run with `npm run test:e2e` (Linux; needs gcc, cargo and
// the `playwright` package). Every step asserts on what the UI shows.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_PATH ?? "playwright");
const PORT = 47231;
const TOKEN = "e2etoken0123456789abcdef0123456789abcd";
const work = mkdtempSync(join(tmpdir(), "echodebug-e2e-"));
const procs = [];
const failures = [];
const step = async (name, f) => {
  const t0 = Date.now();
  try {
    await f();
    console.log(`  ✓ ${name} (${Date.now() - t0} ms)`);
  } catch (e) {
    failures.push(name);
    const shot = join(work, `failed-${failures.length}.png`);
    await page?.screenshot({ path: shot }).catch(() => undefined);
    console.log(`  ✗ ${name}\n    ${String(e?.message ?? e).split("\n").slice(0, 8).join("\n    ")}\n    screenshot: ${shot}`);
  }
};
const expect = (cond, msg) => { if (!cond) throw new Error(msg); };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(f, ms = 15000, every = 250) {
  const t0 = Date.now();
  for (;;) {
    const v = await f().catch(() => undefined);
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error("timed out waiting");
    await wait(every);
  }
}
function start(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
  let log = "";
  p.stdout.on("data", (d) => (log += d));
  p.stderr.on("data", (d) => (log += d));
  procs.push(p);
  return { p, log: () => log };
}
const cleanup = () => { for (const p of procs) try { p.kill("SIGKILL"); } catch { /* gone */ } };
process.on("exit", cleanup);

const relayBin = process.env.ECHODEBUG_RELAY ?? join(root, "src-tauri/target/debug/echodebug-relay");
if (!existsSync(relayBin)) execFileSync("cargo", ["build", "-p", "echo-debug-relay", "--bin", "echodebug-relay"], { cwd: join(root, "src-tauri"), stdio: "inherit" });
const targetBin = join(work, "e2e-target");
execFileSync("gcc", ["-O1", "-g", "-o", targetBin, join(root, "e2e/target.c")]);
const nm = execFileSync("nm", [targetBin]).toString();
const sym = (n) => "0x" + new RegExp(`^([0-9a-f]+) [TtDdBb] ${n}$`, "m").exec(nm)[1].replace(/^0+/, "");

let target = start(targetBin, []);
const relay = start(relayBin, [String(PORT)], { env: { ...process.env, ECHODEBUG_TOKEN: TOKEN, XDG_CONFIG_HOME: work } });
// bind IPv4 explicitly: "localhost" resolves to ::1 on some hosts (GitHub's runners)
const vite = start(join(root, "node_modules/.bin/vite"), ["--host", "127.0.0.1", "--port", "1430", "--strictPort"], { cwd: root });
const startup = async (what, url, ms, log) => {
  try {
    await until(async () => (await fetch(url)).ok, ms);
  } catch {
    console.log(`${what} did not come up at ${url}\n${log().slice(-3000)}`);
    cleanup();
    process.exit(1);
  }
};
await startup("relay", `http://127.0.0.1:${PORT}/health`, 30000, relay.log);
await startup("vite", "http://127.0.0.1:1430/", 90000, vite.log);

const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const page = await browser.newPage({ viewport: { width: 1600, height: 950 } });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const tab = (name) => page.locator(".tab", { hasText: new RegExp(`^${name}$`) }).click();
const attach = async (pid) => {
  await page.locator(".rail-button[aria-label=Targets]").click();
  await page.locator('input[placeholder="Filter processes…"]').fill("e2e-target");
  await page.locator(".panel-header, .panel-head").first().locator("[aria-label=Refresh]").click().catch(() => undefined);
  await until(async () => (await page.locator("tr", { hasText: String(pid) }).count()) > 0);
  await page.locator("tr", { hasText: String(pid) }).locator("button", { hasText: "Attach" }).click();
  await until(async () => (await page.locator(".statusbar, .status-bar").first().innerText()).includes(String(pid)));
};

console.log("EchoDebug end-to-end");
await page.goto(`http://127.0.0.1:1430/?port=${PORT}&token=${TOKEN}`);
await page.locator("button", { hasText: /continue/i }).first().click({ timeout: 10000 }).catch(() => undefined);

await step("rejects a missing token, accepts the right one", async () => {
  expect((await fetch(`http://127.0.0.1:${PORT}/mcp`, { method: "POST", body: "{}" })).status === 401, "no token: expected 401");
  const ok = await fetch(`http://127.0.0.1:${PORT}/mcp`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  expect(ok.status === 200, `token: expected 200, got ${ok.status}`);
});

await step("attaches to the target through the Targets panel", () => attach(target.p.pid));

await step("disassembly lists the target's functions and its text", async () => {
  await tab("Disassembly");
  await page.keyboard.press("Control+g");
  await page.keyboard.type(`e2e-target+${sym("classify")}`);
  // Enter only navigates once the dialog resolved the module-relative address
  await until(async () => /^0x[0-9a-f]+$/.test((await page.locator("[role=dialog] .mono.faint").innerText()).trim()));
  await page.keyboard.press("Enter");
  await until(async () => (await page.locator(".insn-row").count()) > 5);
  const text = await page.locator(".insn-row .insn-text").first().innerText();
  expect(/endbr64|push|mov|and/.test(text), `first instruction looks wrong: ${text}`);
});

await step("CFG resolves the switch table", async () => {
  await tab("CFG");
  const t = await until(async () => {
    const s = await page.locator(".toolbar .mono.faint").first().innerText();
    return /(\d+) blocks/.test(s) && s;
  });
  expect(Number(/(\d+) blocks/.exec(t)[1]) >= 9, `too few blocks: ${t}`);
});

await step("scanner narrows the counter with an in-app next scan and undoes it", async () => {
  await page.locator(".panel select").nth(1).selectOption("unknown");
  await page.locator(".panel select").nth(2).selectOption("e2e-target");
  await page.locator("button", { hasText: "First scan" }).click();
  const first = await until(async () => { const s = await page.locator(".panel-section .faint[title]").first().innerText(); return /in app/.test(s) && s; });
  await page.locator(".panel select").nth(1).selectOption("increased");
  await page.locator("button", { hasText: "Next scan" }).click();
  await until(async () => (await page.locator(".panel-section .faint[title]").first().innerText()) !== first);
  await page.locator("button", { hasText: "Undo" }).click();
  await until(async () => (await page.locator(".panel-section .faint[title]").first().innerText()) === first);
});

await step("memory find locates a string backwards", async () => {
  await tab("Memory");
  await page.locator('input[placeholder="address · module+0x…"]').fill(`e2e-target+${sym("counter")}`);
  await page.keyboard.press("Enter");
  await page.locator("select").filter({ hasText: "utf16" }).first().selectOption("ascii");
  await page.locator('input[placeholder="find ascii"]').fill("hello from the EchoDebug");
  await page.keyboard.press("Shift+Enter");
  await until(async () => (await page.locator(".hex-cell[data-range=true]").count()) >= 20, 30000);
});

await step("batch decrypt recovers both strings", async () => {
  await tab("Decrypt");
  await page.locator('input[placeholder="address of the decryption routine"]').fill(`e2e-target+${sym("dec")}`);
  await page.keyboard.press("Enter");
  await page.locator("button", { hasText: "Decrypt every call site" }).click();
  const got = await until(async () => { const t = await page.locator("td.accent").allInnerTexts(); return t.length >= 2 && t; }, 30000);
  expect(got.some((t) => t.includes("api.example.com")) && got.some((t) => t.includes("decrypted ok")), `got ${got}`);
});

await step("debugger stops at a breakpoint and detaches", async () => {
  await tab("Debugger");
  await page.locator("button", { hasText: "Attach debugger" }).click();
  await page.locator('input[placeholder="add: address · module+0x…"]').fill(`e2e-target+${sym("classify")}`);
  await page.keyboard.press("Enter");
  await page.locator("[aria-label=Continue]").click();
  await until(async () => (await page.locator(".vlist.mono div", { hasText: "breakpoint" }).count()) > 0);
  await page.locator("[aria-label='Detach debugger']").click();
  await until(async () => (await page.locator("button", { hasText: "Attach debugger" }).count()) > 0);
});

await step("YARA matches the greeting", async () => {
  await tab("YARA");
  await page.locator("textarea").fill('rule greeting { strings: $g = "hello from the EchoDebug" condition: $g }');
  await page.locator("button.primary", { hasText: /Scan/ }).last().click();
  await until(async () => (await page.locator(".accent.mono", { hasText: "greeting" }).count()) > 0);
});

await step("script console runs against the ed API", async () => {
  await tab("Script");
  await page.locator("textarea").first().fill('const m = ed.module(); ed.names.set(ed.addr(m.name + "+' + sym("classify") + '"), "classify_e2e"); return m.name;');
  await page.locator("[aria-label='Run (Ctrl+Enter)']").click();
  await until(async () => (await page.locator("pre").filter({ hasText: "⇒ e2e-target" }).count()) > 0);
});

await step("module projects bring the name back after the target restarts at a new base", async () => {
  await wait(2000); // projects save debounced
  target.p.kill("SIGKILL");
  target = start(targetBin, []);
  await wait(300);
  await attach(target.p.pid);
  await tab("Disassembly");
  await until(async () => (await page.locator(".fn-row", { hasText: "classify_e2e" }).count()) > 0, 20000);
});

await step("no uncaught errors in the page", async () => expect(errors.length === 0, errors.join("\n")));

await browser.close();
cleanup();
if (failures.length) {
  console.log(`\n${failures.length} failed: ${failures.join(", ")}\nrelay log:\n${relay.log().slice(-2000)}`);
  process.exit(1);
}
console.log("\nall end-to-end steps passed");
process.exit(0);
