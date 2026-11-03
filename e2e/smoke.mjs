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
// views that are not in the tab strip open through the "All views" menu
const tab = async (name) => {
  const t = page.locator(".tab", { hasText: new RegExp(`^${name}$`) });
  if (await t.count()) return t.first().click();
  await page.locator("[aria-label='All views']").click();
  await page.locator('input[placeholder="Find a view…"]').fill(name);
  await page.locator(".views-item", { hasText: new RegExp(`^${name}`) }).first().click();
};
const attach = async (pid) => {
  // the active rail button folds the panel away: only click when Targets is not the shown panel.
  // Ask the rail, not the panel: the panel loads lazily, so its input can be missing for a moment.
  const targets = page.locator(".rail-button[aria-label=Targets]");
  if ((await targets.getAttribute("data-active")) !== "true") await targets.click();
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

await step("emulated debugger steps classify and runs it to its return", async () => {
  await tab("Emu Debugger");
  await page.locator('input[placeholder="function address · game.exe+0x1234"]').fill(`e2e-target+${sym("classify")}`);
  await page.locator("button", { hasText: "Start session" }).click();
  await until(async () => (await page.locator("text=session started").count()) > 0);
  await page.locator("[aria-label='Step one instruction']").click();
  await until(async () => (await page.locator("text=stepped 1 instruction").count()) > 0);
  await page.locator("[aria-label='Run to a breakpoint, a return or a fault']").click();
  await until(async () => (await page.locator("text=the function returned").count()) > 0);
});

await step("trace records classify in the emulator and scrubs back through it", async () => {
  await tab("Trace");
  await page.locator('input[placeholder="empty: the current session"]').fill(`e2e-target+${sym("classify")}`);
  await page.getByRole("button", { name: "Record", exact: true }).click();
  await until(async () => (await page.locator("text=stopped: returned").count()) > 0, 20000);
  const n = Number(await page.locator("input[type=range]").getAttribute("max"));
  expect(n > 3, `too few steps: ${n}`);
  expect((await page.locator("table tbody tr").count()) > 3, "the instruction list is empty");
  // scrub: to the end with the slider, then one step back
  await page.locator("input[title=position]").fill(String(n));
  await page.locator("[aria-label='Step back (←)']").click();
  await until(async () => (await page.locator(".label", { hasText: `Registers at ${n - 1}` }).count()) > 0);
  await page.locator(".kv span[title='Where did this value come from?']").first().click();
  await until(async () => (await page.locator("text=/Where did \\w+ come from/").count()) > 0);
});

await step("page monitor sees the counter's page change", async () => {
  await tab("Monitors");
  await page.locator('input[placeholder="address · module+0x…"]').last().fill(`e2e-target+${sym("counter")}`);
  await page.locator("button.primary", { hasText: /^Watch$/ }).click();
  await until(async () => (await page.locator("text=/[1-9][0-9]* changes/").count()) > 0, 15000);
});

await step("lifter deobfuscates classify's emulated run and lifts a block", async () => {
  await tab("Lifter");
  await page.locator('input[placeholder="start · module+0x…"]').fill(`e2e-target+${sym("classify")}`);
  await page.locator("button", { hasText: "Emulate & deobfuscate" }).click();
  await until(async () => (await page.locator("text=/\\d+ kept/").count()) > 0, 20000);
  expect((await page.locator(".lift-effects").first().innerText()).includes("rax"), "rax is among the effects");
  await page.locator(".tabs .tab", { hasText: /^Block$/ }).click();
  await page.locator("button", { hasText: "Lift block" }).click();
  await until(async () => (await page.locator("th", { hasText: /dead\)/ }).count()) > 0);
});

await step("lifter devirtualizes the toy VM: dispatcher, handlers, virtual stream", async () => {
  await page.locator(".tabs .tab", { hasText: /^Devirtualize$/ }).click();
  await page.locator('input[placeholder="start · module+0x…"]').fill(`e2e-target+${sym("vm_run")}`);
  await page.locator('input[placeholder="regs: rcx=0x10, rdx=…"]').fill(`rdi=e2e-target+${sym("vm_code")}`);
  await page.locator("button", { hasText: "Emulate & devirtualize" }).click();
  const kv = await until(async () => { const t = await page.locator(".kv").first().innerText(); return /dispatcher/.test(t) && t; }, 20000);
  const n = Number(/(\d+) distinct/.exec(kv)?.[1] ?? 0);
  expect(n >= 5, `expected at least 5 distinct handlers, got: ${kv}`);
  expect((await page.locator(".vtrace .pill").count()) >= 8, "virtual instruction stream (the bytecode has 9 ops before halt)");
});

await step("snapshot diff in the backend sees the counter change", async () => {
  await tab("Monitors");
  await page.locator('input[placeholder="module name or address"]').fill(`e2e-target+${sym("counter")}`);
  await page.locator('input[title="size (ignored for a module)"]').fill("0x100");
  await page.locator("button", { hasText: /^Snapshot$/ }).click();
  await until(async () => (await page.locator("text=/baseline/").count()) > 0);
  await wait(300);
  await page.locator("button", { hasText: "What changed?" }).click();
  await until(async () => (await page.locator("text=/[1-9][0-9]* bytes changed/").count()) > 0);
});

await step("xref scan in the backend finds dec's call sites", async () => {
  await tab("Xrefs");
  await page.locator('input[placeholder="Address or module+offset…"]').fill(`e2e-target+${sym("dec")}`);
  await page.locator("button", { hasText: /^Everywhere$/ }).click();
  await until(async () => (await page.locator(".tag", { hasText: /^call$/ }).count()) >= 2, 20000);
});

await step("YARA matches the greeting", async () => {
  await tab("YARA");
  await page.locator("textarea").fill('rule greeting { strings: $g = "hello from the EchoDebug" condition: $g }');
  await page.locator("button.primary", { hasText: /Scan/ }).last().click();
  await until(async () => (await page.locator(".accent.mono", { hasText: "greeting" }).count()) > 0);
});

await step("heap explorer walks the target's malloc arena (view and MCP tools)", async () => {
  await tab("Heap");
  await until(async () => (await page.locator(".mono", { hasText: /^main_arena$/ }).count()) > 0, 20000);
  const call = async (name, args) => {
    const r = await fetch(`http://127.0.0.1:${PORT}/mcp`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
    const j = await r.json();
    expect(!j.result?.isError, `${name}: ${JSON.stringify(j).slice(0, 400)}`);
    return j.result.structuredContent;
  };
  const heaps = await call("heaps", {});
  expect(heaps.platform === "glibc" && heaps.heaps.some((h) => h.label === "main_arena"), `heaps: ${JSON.stringify(heaps).slice(0, 400)}`);
  const mods = await call("list_modules", {});
  const base = BigInt(mods.modules.find((m) => m.name === "e2e-target").base);
  const ptr = await call("read_memory", { address: "0x" + (base + BigInt(sym("heap_note"))).toString(16), size: 8 });
  const note = BigInt("0x" + ptr.data.match(/../g).reverse().join(""));
  const found = await call("heap_find", { address: "0x" + (note + 5n).toString(16) });
  expect(found.found && found.chunk.state === "in-use" && found.chunk.user === "0x" + note.toString(16) && found.chunk.user_size >= 0x123, `heap_find: ${JSON.stringify(found).slice(0, 400)}`);
  const page1 = await call("heap_chunks", { state: "used", limit: 5 });
  expect(page1.total >= 1 && page1.chunks.length >= 1, `heap_chunks: ${JSON.stringify(page1).slice(0, 400)}`);
});

await step("MCP panel: test call, live clients, tool profiles, tester and a stdio client", async () => {
  const modern = (id, method, params = {}) => ({
    headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2026-07-28", "mcp-method": method, ...(params.name ? { "mcp-name": params.name } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "e2e-client", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} } } }),
  });
  const rpc = async (id, method, params) => (await (await fetch(`http://127.0.0.1:${PORT}/mcp`, { method: "POST", ...modern(id, method, params) })).json());
  const listed = async () => (await rpc(1, "tools/list")).result.tools.map((t) => t.name);
  await page.locator(".rail-button[aria-label='MCP Server']").click();
  // the first-run card's test call goes over the real HTTP endpoint with the token
  await page.locator("button", { hasText: "Run a test call" }).click();
  await until(async () => (await page.locator(".mcp-ok", { hasText: "MCP works" }).count()) > 0);
  // an outside 2026-07-28 client appears in the connection list with its clientInfo
  expect((await rpc(2, "server/discover")).result.supportedVersions[0] === "2026-07-28", "server/discover");
  await until(async () => (await page.locator(".mcp-session", { hasText: "e2e-client" }).count()) > 0);
  // the app window serves its tools: listed; a profile hides what it denies
  expect((await listed()).includes("list_names"), "ui_* tools listed while the window is open");
  await page.locator(".mcp-preset", { hasText: "Read-only analysis" }).click();
  await until(async () => !(await listed()).includes("write_memory"));
  expect((await listed()).includes("read_memory"), "read-only keeps reads");
  await page.locator(".mcp-preset", { hasText: "Full control" }).click();
  await until(async () => (await listed()).includes("write_memory"));
  // the tester runs a tool through the MCP path and shows what a client gets
  await page.locator(".panel-section input[placeholder='Filter…']").fill("list_modules");
  await page.locator(".mcp-tool", { hasText: "list_modules" }).click();
  await page.locator(".mcp-call button", { hasText: "Call tool" }).click();
  await until(async () => (await page.locator(".mcp-call .mcp-result", { hasText: "e2e-target" }).count()) > 0);
  // without the desktop app, client setup offers snippets
  await page.locator(".mcp-snippets summary").click();
  await until(async () => (await page.locator(".mcp-snippet pre", { hasText: "mcpServers" }).count()) > 0);
  // a stdio client: echodebug-relay --stdio bridges to this relay
  const child = spawn(relayBin, ["--stdio", String(PORT)], { env: { ...process.env, ECHODEBUG_TOKEN: TOKEN, XDG_CONFIG_HOME: work }, stdio: ["pipe", "pipe", "ignore"] });
  procs.push(child);
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e-stdio", version: "1" } } }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "status", arguments: {} } }) + "\n");
  await until(async () => out.split("\n").some((l) => l.includes('"id":2') && l.includes("structuredContent")));
  await until(async () => (await page.locator(".mcp-session", { hasText: "e2e-stdio" }).count()) > 0);
  // disconnect it from the panel
  await page.locator(".mcp-session", { hasText: "e2e-stdio" }).locator("[data-tip^='Disconnect']").click();
  await until(async () => (await page.locator(".mcp-session", { hasText: "e2e-stdio" }).count()) === 0);
  child.kill("SIGKILL");
  await page.locator(".rail-button[aria-label=Targets]").click();
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

await step("threads view unwinds the target's main thread into main()", async () => {
  await tab("Threads");
  await until(async () => (await page.locator("td", { hasText: /^main(\+0x[0-9a-f]+)?$/ }).count()) > 0, 20000);
  expect((await page.locator(".pill", { hasText: /^main$/ }).count()) > 0, "main thread not marked");
  await page.locator("button", { hasText: "Handles" }).click();
  await until(async () => (await page.locator("td", { hasText: /^(file|device|pipe|socket)$/ }).count()) > 0);
});

await step("TLS & SEH says an ELF module has no PE tables", async () => {
  await tab("TLS & SEH");
  await until(async () => (await page.locator(".empty-title", { hasText: "is not a PE module" }).count()) > 0);
});

await step("value graph plots the counter from the watchlist", async () => {
  await page.locator(".rail-button[aria-label='Watchlist & Bookmarks']").click();
  const box = page.locator('input[placeholder="address or module+0x…"]').first();
  await box.fill(`e2e-target+${sym("counter")}`);
  await box.press("Enter");
  await page.locator("[aria-label='Graph this']").first().click();
  await until(async () => (await page.locator(".tabs-wrap .tab[data-active=true]").innerText()).startsWith("Value Graphs"));
  // samples arrive (10 Hz poll) and the stats row fills in
  await until(async () => Number(await page.locator(".vgraph-stats tbody tr td.faint").first().innerText()) > 5);
  const plot = page.locator(".vgraph-plot");
  const bb = await plot.boundingBox();
  await page.mouse.move(bb.x + bb.width - 40, bb.y + bb.height / 2);
  await until(async () => (await page.locator(".vgraph-tip").count()) > 0);
  await page.mouse.move(bb.x + bb.width / 2, bb.y + bb.height / 2);
  await page.mouse.wheel(0, -300);
  await page.locator("[aria-label='Pause sampling']").click();
  await until(async () => (await page.locator(".vgraph-note", { hasText: "Paused" }).count()) > 0);
  await page.locator("[aria-label='Resume sampling']").click();
});

await step("search everything finds a name and jumps to it", async () => {
  await page.keyboard.press("Control+Shift+F");
  await page.locator(".search-dialog .palette-input").fill("clasify e2e");
  await until(async () => (await page.locator(".search-dialog .palette-item", { hasText: "classify_e2e" }).count()) > 0);
  // exports / modules are indexed too
  await page.locator(".search-dialog .palette-input").fill("e2e-target");
  await until(async () => (await page.locator(".search-dialog .palette-group", { hasText: "Modules" }).count()) > 0);
  await page.locator(".search-dialog .palette-input").fill("classify_e2e");
  await until(async () => (await page.locator(".search-dialog .palette-item[data-active=true]", { hasText: "classify_e2e" }).count()) > 0);
  await page.keyboard.press("Enter");
  await until(async () => (await page.locator(".search-dialog").count()) === 0);
  await until(async () => (await page.locator(".tabs-wrap .tab[data-active=true]").innerText()).startsWith("Disassembly"));
});

await step("views menu, tab close and panel toggles", async () => {
  await page.locator("[aria-label='All views']").click();
  await page.locator('input[placeholder="Find a view…"]').fill("hooks");
  await page.keyboard.press("Enter");
  await until(async () => (await page.locator(".tabs-wrap .tab[data-active=true]").innerText()).startsWith("Hooks"));
  await page.locator("[aria-label='Close Hooks']").click();
  await until(async () => (await page.locator(".tabs-wrap .tab", { hasText: /^Hooks$/ }).count()) === 0);
  await page.keyboard.press("Control+j");
  await until(async () => (await page.locator("[aria-label='Toggle output'][data-active=false]").count()) > 0);
  await page.keyboard.press("Control+j");
  await page.keyboard.press("F1");
  await until(async () => (await page.locator("[aria-label='Keyboard shortcuts'][role=dialog]").count()) > 0);
  await page.keyboard.press("Escape");
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
