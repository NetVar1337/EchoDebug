// EchoDebug example plugin (read-only: "permissions": [] in manifest.json).
//
// A plugin is one ES module that exports activate(ctx). ctx holds:
//   ctx.ed          the Script tab's API (read, readU64, disasm, modules, module, label, names.get, ui, request, …)
//                   with the manifest's permissions enforced
//   ctx.log(...)    prints to the Output panel
//   ctx.navigate(a) opens the disassembly at an address
//   ctx.registerView / registerCommand / registerAddressAction / registerAnalysis
// Install: copy this folder into <config>/EchoDebug/plugins/ and enable it in Settings → Plugins.

const hex = (v) => "0x" + BigInt(v).toString(16);

export function activate(ctx) {
  const { ed } = ctx;

  // A view: gets an empty container element and renders into it with plain DOM.
  ctx.registerView({
    id: "modules",
    title: "Modules",
    render(container) {
      const draw = () => {
        const mods = ed.modules();
        container.replaceChildren();
        const head = document.createElement("div");
        head.className = "faint";
        head.textContent = mods.length ? `${mods.length} modules · click a row to disassemble its base` : "Attach to a process to see its modules.";
        container.append(head);
        const table = document.createElement("table");
        table.className = "table mono";
        table.innerHTML = "<thead><tr><th>Module</th><th>Base</th><th>Size</th><th>Names</th></tr></thead>";
        const body = document.createElement("tbody");
        const names = ed.names.all();
        for (const m of [...mods].sort((a, b) => b.size - a.size)) {
          const base = BigInt(m.base);
          const inside = names.filter((n) => {
            const a = BigInt("0x" + n.address.replace(/^0x/, ""));
            return a >= base && a < base + BigInt(m.size);
          }).length;
          const tr = document.createElement("tr");
          for (const text of [m.name, m.base, `${(m.size / 1024).toFixed(0)} KiB`, String(inside)]) {
            const td = document.createElement("td");
            td.textContent = text;
            tr.append(td);
          }
          tr.style.cursor = "pointer";
          tr.onclick = () => ctx.navigate(m.base);
          body.append(tr);
        }
        table.append(body);
        container.append(table);
      };
      draw();
      const timer = setInterval(draw, 3000);
      return () => clearInterval(timer); // called when the view closes or the plugin is disabled
    },
  });

  // An analysis: returns { columns, rows }; addresses (0x…) in the table are clickable.
  ctx.registerAnalysis({
    id: "pointer-table",
    title: "Pointer table",
    description: "Reads qwords at an address and shows which ones point into a loaded module",
    params: [{ name: "address", label: "address · module+0x…" }, { name: "count", label: "qwords", default: "32" }],
    async run({ address, count }) {
      if (!address) throw new Error("enter an address");
      const n = Math.max(1, Math.min(4096, Number(count) || 32));
      const start = ed.addr(address);
      const bytes = await ed.read(start, n * 8);
      if (!bytes) throw new Error(`cannot read ${hex(start)}`);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const rows = [];
      for (let i = 0; i < n; i++) {
        const v = view.getBigUint64(i * 8, true);
        const label = ed.label(v);
        rows.push([hex(start + BigInt(i * 8)), `+0x${(i * 8).toString(16)}`, hex(v), label.startsWith("0x") ? "" : label]);
      }
      return { columns: ["address", "offset", "value", "points into"], rows };
    },
  });

  // A command palette entry (Ctrl+K).
  ctx.registerCommand({
    id: "largest-module",
    label: "Disassemble the largest module",
    run() {
      const mods = ed.modules();
      if (!mods.length) return ctx.log("no modules: attach first");
      const m = mods.reduce((a, b) => (b.size > a.size ? b : a));
      ctx.navigate(m.base);
    },
  });

  // A context-menu entry on addresses (right-click in the disassembly or the names panel).
  ctx.registerAddressAction({
    id: "peek",
    label: "Peek 16 bytes (Output)",
    async run(address) {
      const b = await ed.read(address, 16);
      ctx.log(ed.label(address), b ? ed.toHex(b) : "unreadable");
    },
  });
}

export function deactivate() {
  // optional: registrations are removed by EchoDebug; free anything else here
}
