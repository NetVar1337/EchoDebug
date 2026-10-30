#!/usr/bin/env node
// Lints an Echo AngelScript file with the echo-angelscript-lsp parser + analyzer.
// Usage: node scripts/lint-agent.mjs <path-to-built-echo-angelscript-lsp> <file.as>
// Reports lexer/parser errors and identifiers that resolve to no declaration (Echo API decls
// + the file itself). Exit code 1 on any finding.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const [lspDir, file] = process.argv.slice(2);
if (!lspDir || !file) {
  console.error("usage: node scripts/lint-agent.mjs <echo-angelscript-lsp dir> <file.as>");
  process.exit(2);
}
const require = createRequire(import.meta.url);
const out = join(resolve(lspDir), "server", "out");
const { Lexer, Parser } = require(join(out, "parser", "index.js"));
const { Analyzer, TypeChecker } = require(join(out, "analyzer", "index.js"));
const { loadApiScope } = require(join(out, "api", "loader.js"));

// Std string-addon globals the LSP's API decls don't declare.
const ADDON_GLOBALS = new Set(["parseFloat", "parseInt", "parseUInt", "formatInt", "formatUInt", "formatFloat"]);
// The LSP declares these inside `namespace process`; Echo's docs (and working scripts) use them
// unqualified, so expose them globally too.
const PROCESS_TYPES = ["attach_data", "module_entry", "memory_region"];

const src = readFileSync(file, "utf8");
const { tokens, errors: lexErrors, docs } = new Lexer(src).tokenize();
const { module, errors: parseErrors } = new Parser(tokens, docs).parse();
const api = loadApiScope();
const processNs = api.lookupLocal("process")?.find((sym) => sym.innerScope)?.innerScope;
for (const name of PROCESS_TYPES) for (const sym of processNs?.lookupLocal(name) ?? []) api.declare(sym);
const analysis = new Analyzer().analyze(module, api);
// Second pass resolves obj.member references the first pass leaves open.
new TypeChecker().check(module, analysis.global, analysis.references);

const problems = [];
const at = (p) => `${file}:${p.line + 1}:${p.column + 1}`;
for (const e of [...lexErrors, ...parseErrors]) problems.push(`${at(e.startPos)} error: ${e.message}`);
for (const r of analysis.references) {
  // "<ctor>": the analyzer does not model `Type var(args);` declarations.
  if (r.symbol || ADDON_GLOBALS.has(r.name) || r.name === "<ctor>") continue;
  problems.push(`${at(r.range.start)} unresolved: ${r.name}`);
}
for (const p of problems) console.log(p);
console.log(`${problems.length} problem(s) in ${file}`);
process.exit(problems.length ? 1 : 0);
