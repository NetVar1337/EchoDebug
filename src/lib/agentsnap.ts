// Agent snapshot + rollback (#34): before the auto-updater overwrites %APPDATA%\scripts\echo_debug.as,
// the current agent script is copied into snapshots\ and only the last `keep` are kept; rollback
// copies the newest snapshot back. The fs is injected so this is testable without a real disk.

export type AgentFs = {
  readFile(p: string): Promise<string>;
  writeFile(p: string, data: string): Promise<void>;
  mkdir(p: string): Promise<void>;
  list(p: string): Promise<string[]>;
};

export const kSnapshotPrefix = "echo_debug.";
export const kSnapshotExt = ".as.snap";

/** "snapshots\echo_debug.2026-07-28T12-00-00.000Z.as.snap" — sortable, collision-free. */
export function snapshotName(d = new Date()): string {
  return `${kSnapshotPrefix}${d.toISOString().replace(/[:.]/g, "-")}${kSnapshotExt}`;
}

export function isSnapshot(name: string): boolean {
  return name.startsWith(kSnapshotPrefix) && name.endsWith(kSnapshotExt);
}

/** Copies `srcPath` into `dir` under a fresh snapshot name; prunes to the newest `keep`. Returns the snapshot path. */
export async function snapshotAgent(fs: AgentFs, srcPath: string, dir: string, keep = 5): Promise<string> {
  await fs.mkdir(dir).catch(() => undefined);
  const snap = `${dir}/${snapshotName()}`;
  const content = await fs.readFile(srcPath);
  await fs.writeFile(snap, content);
  const all = (await fs.list(dir)).filter(isSnapshot).sort(); // ISO-ish names sort chronologically
  for (const old of all.slice(0, Math.max(0, all.length - keep))) {
    await fs.writeFile(`${dir}/${old}`, "\0prune").catch(() => undefined); // marker; real pruning needs fs.rm
  }
  return snap;
}

export type PruneFs = AgentFs & { rm?(p: string): Promise<void> };

/** Same as snapshotAgent but actually deletes old snapshots when the fs supports rm. */
export async function snapshotAgentPruned(fs: PruneFs, srcPath: string, dir: string, keep = 5): Promise<string> {
  const snap = await snapshotAgent(fs, srcPath, dir, keep);
  if (fs.rm) {
    const all = (await fs.list(dir)).filter(isSnapshot).sort();
    for (const old of all.slice(0, Math.max(0, all.length - keep))) await fs.rm(`${dir}/${old}`);
  }
  return snap;
}

/** Newest snapshot in `dir`, or null. */
export async function latestSnapshot(fs: AgentFs, dir: string): Promise<string | null> {
  const all = (await fs.list(dir)).filter(isSnapshot).sort();
  return all.length ? `${dir}/${all[all.length - 1]}` : null;
}

/** Copies the newest snapshot back over `srcPath`. Returns false when there is nothing to restore. */
export async function rollbackAgent(fs: AgentFs, srcPath: string, dir: string): Promise<boolean> {
  const snap = await latestSnapshot(fs, dir);
  if (!snap) return false;
  await fs.writeFile(srcPath, await fs.readFile(snap));
  return true;
}
