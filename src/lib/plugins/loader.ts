// Finding, loading and activating plugins. Desktop app only: plugins live in
// <config>/EchoDebug/plugins/<folder>/ (manifest.json + one self-contained ES module).
import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "@/lib/tauri";
import { validateManifest, type Manifest } from "./manifest";
import { makePluginContext, type PluginContext } from "./api";
import { unregisterPlugin } from "./registry";

export type Discovered = { dir: string; manifest: Manifest | null; errors: string[]; warnings: string[] };
export type PluginModule = { activate?: (ctx: PluginContext) => unknown; deactivate?: () => unknown; default?: unknown };
export type Active = { id: string; dispose: () => void; deactivate?: () => unknown };

type Folder = { dir: string; manifest?: string | null; error?: string | null };

/** Folders → validated manifests; a second folder with an id already taken is an error. */
export function checkFolders(folders: readonly Folder[]): Discovered[] {
  const seen = new Set<string>();
  return folders.map((f) => {
    if (!f.manifest) return { dir: f.dir, manifest: null, errors: [f.error || "manifest.json missing"], warnings: [] };
    const r = validateManifest(f.manifest);
    if (!r.ok) return { dir: f.dir, manifest: null, errors: r.errors, warnings: [] };
    if (seen.has(r.manifest.id)) return { dir: f.dir, manifest: r.manifest, errors: [`id ${r.manifest.id} is already used by another plugin folder`], warnings: r.warnings };
    seen.add(r.manifest.id);
    return { dir: f.dir, manifest: r.manifest, errors: [], warnings: r.warnings };
  });
}

export async function discoverPlugins(): Promise<Discovered[]> {
  if (!isTauri()) return [];
  return checkFolders(await invoke<Folder[]>("list_plugins"));
}

export async function pluginsDir(): Promise<string | null> {
  return isTauri() ? invoke<string>("plugins_dir") : null;
}

/** Imports module source as an ES module (a blob: URL; relative imports are not supported, bundle the plugin). */
export async function importSource(source: string): Promise<PluginModule> {
  const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
  try {
    return (await import(/* @vite-ignore */ url)) as PluginModule;
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** Calls the module's activate(ctx); on failure everything it registered is removed again. */
export async function activateModule(manifest: Manifest, mod: PluginModule, print: (...a: unknown[]) => void): Promise<Active> {
  const activate = typeof mod.activate === "function" ? mod.activate : typeof mod.default === "function" ? (mod.default as PluginModule["activate"]) : undefined;
  if (!activate) throw new Error(`${manifest.entry} exports no activate(ctx) function`);
  const { ctx, dispose } = makePluginContext(manifest, print);
  try {
    await activate(ctx);
  } catch (e) {
    dispose();
    unregisterPlugin(manifest.id);
    throw e;
  }
  return { id: manifest.id, dispose, deactivate: typeof mod.deactivate === "function" ? mod.deactivate : undefined };
}

export async function loadPlugin(d: Discovered, print: (...a: unknown[]) => void): Promise<Active> {
  if (!d.manifest || d.errors.length) throw new Error(d.errors.join("; ") || "invalid plugin");
  const source = await invoke<string>("read_plugin_file", { dir: d.dir, path: d.manifest.entry });
  return activateModule(d.manifest, await importSource(source), print);
}

export async function unloadPlugin(a: Active): Promise<void> {
  try {
    await a.deactivate?.();
  } finally {
    a.dispose();
    unregisterPlugin(a.id);
  }
}
