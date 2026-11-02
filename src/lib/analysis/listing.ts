// Listing export: a function or range as an .asm text file or a C byte array.

export type ListingLine = { address: string; bytes: string; text: string };

export function toAsm(lines: readonly ListingLine[], opts: { title?: string; nameOf?: (a: string) => string; commentOf?: (a: string) => string; label?: (a: string) => string } = {}): string {
  const out = [`; ${opts.title ?? "EchoDebug listing"}`, `; ${lines.length} instructions`, ""];
  for (const l of lines) {
    const name = opts.nameOf?.(l.address);
    if (name) out.push(`${name}:`);
    const where = opts.label?.(l.address) ?? l.address;
    const cmt = opts.commentOf?.(l.address);
    const bytes = l.bytes.replace(/(..)/g, "$1 ").trim();
    out.push(`    ${l.text.padEnd(44)} ; ${where.padEnd(28)} ${bytes}${cmt ? `  // ${cmt}` : ""}`);
  }
  return out.join("\n") + "\n";
}

export function toCArray(lines: readonly ListingLine[], name = "code"): string {
  const bytes = lines.flatMap((l) => l.bytes.match(/../g) ?? []);
  const rows: string[] = [];
  for (let i = 0; i < bytes.length; i += 12) rows.push("    " + bytes.slice(i, i + 12).map((b) => `0x${b}`).join(", ") + ",");
  return `// ${lines[0]?.address ?? ""}, ${bytes.length} bytes\nunsigned char ${name}[${bytes.length}] = {\n${rows.join("\n")}\n};\n`;
}
