// EchoDebug plugin manifests (`manifest.json` in each folder of <config>/EchoDebug/plugins).
//
//   { "id": "acme.vtable-tools", "name": "VTable tools", "version": "1.2.0",
//     "entry": "index.js", "permissions": ["write"], "description": "…", "author": "…" }

/** What a plugin may do beyond reading. Without any of these it is read-only. */
export const kPermissions = {
  write: "Write target memory through the journal (every write is listed in Patches and can be reverted), use stateful verbs (scanner, emulator, attach)",
  annotate: "Change your names, comments and struct types",
} as const;
export type Permission = keyof typeof kPermissions;

export type Manifest = {
  id: string;
  name: string;
  version: string;
  /** ES module, relative to the plugin folder */
  entry: string;
  permissions: Permission[];
  description?: string;
  author?: string;
};

export type ManifestResult = { ok: true; manifest: Manifest; warnings: string[] } | { ok: false; errors: string[] };

export const kIdPattern = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const kVersion = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** A relative path inside the plugin folder: no absolute paths, drive letters, `..` or backslashes. */
export function safeEntry(p: string): boolean {
  if (!p || p.length > 200 || p.includes("\\") || p.includes("\0") || p.startsWith("/") || /^[A-Za-z]:/.test(p)) return false;
  const parts = p.split("/");
  return parts.every((x) => x !== ".." && x !== "" && x !== ".") && /\.(m?js)$/.test(p);
}

/** Validates parsed manifest JSON (or its text). */
export function validateManifest(raw: unknown): ManifestResult {
  let v = raw;
  if (typeof v === "string") {
    try {
      v = JSON.parse(v);
    } catch (e) {
      return { ok: false, errors: [`manifest.json is not valid JSON: ${e instanceof Error ? e.message : e}`] };
    }
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return { ok: false, errors: ["manifest.json must hold an object"] };
  const m = v as Record<string, unknown>;
  const errors: string[] = [];
  const warnings: string[] = [];
  const str = (k: string, max: number): string | undefined => {
    const x = m[k];
    if (typeof x !== "string" || !x.trim()) {
      errors.push(`"${k}" is required (a non-empty string)`);
      return undefined;
    }
    if (x.length > max) errors.push(`"${k}" is longer than ${max} characters`);
    return x.trim();
  };
  const id = str("id", 64);
  if (id !== undefined && !kIdPattern.test(id)) errors.push(`"id" must be 2-64 characters of a-z, 0-9, '.', '_' or '-' and start with a letter or digit (got "${id}")`);
  const name = str("name", 80);
  const version = str("version", 40);
  if (version !== undefined && !kVersion.test(version)) errors.push(`"version" must be semver, e.g. 1.0.0 (got "${version}")`);
  const entry = str("entry", 200);
  if (entry !== undefined && !safeEntry(entry)) errors.push(`"entry" must be a .js or .mjs file inside the plugin folder (got "${entry}")`);
  let permissions: Permission[] = [];
  if (m.permissions === undefined) permissions = [];
  else if (!Array.isArray(m.permissions)) errors.push(`"permissions" must be an array`);
  else {
    for (const p of m.permissions) {
      if (typeof p !== "string" || !(p in kPermissions)) errors.push(`unknown permission ${JSON.stringify(p)} (known: ${Object.keys(kPermissions).join(", ")})`);
      else if (!permissions.includes(p as Permission)) permissions.push(p as Permission);
    }
  }
  for (const k of ["description", "author"] as const) {
    if (m[k] !== undefined && typeof m[k] !== "string") errors.push(`"${k}" must be a string`);
  }
  const known = new Set(["id", "name", "version", "entry", "permissions", "description", "author", "$schema"]);
  for (const k of Object.keys(m)) if (!known.has(k)) warnings.push(`unknown field "${k}" ignored`);
  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    warnings,
    manifest: {
      id: id!, name: name!, version: version!, entry: entry!, permissions,
      description: typeof m.description === "string" ? m.description.slice(0, 500) : undefined,
      author: typeof m.author === "string" ? m.author.slice(0, 120) : undefined,
    },
  };
}

/** One line per permission, for the enable prompt. Read-only plugins get the read line only. */
export function describePermissions(perms: readonly Permission[]): string[] {
  return ["Read target memory, modules and disassembly, and run EchoDebug's analyses", ...perms.map((p) => kPermissions[p])];
}
