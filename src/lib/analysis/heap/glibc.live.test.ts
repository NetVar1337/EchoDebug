// Linux integration test: compiles a small C program that mallocs and frees known sizes, then runs
// the glibc explorer against the live process through /proc/<pid>/mem (no relay involved).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, readSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { HeapMem } from "./reader";
import { exploreGlibc, glibcVersion } from "./glibc";
import { findChunk, type HeapReport } from "./model";

const kProgram = String.raw`
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
static void *thr[4];
static pthread_barrier_t ready, never;
static void *worker(void *arg) {
  (void)arg;
  for (int i = 0; i < 4; i++) { thr[i] = malloc(0x88); memset(thr[i], 0x77, 0x88); }
  free(thr[3]);
  pthread_barrier_wait(&ready);
  pthread_barrier_wait(&never); /* keep the thread (and its tcache) alive */
  return NULL;
}
int main(void) {
  prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0); /* getchar must not malloc a buffer (that would consolidate the fastbins) */
  static const size_t sizes[5] = { 0x18, 0x48, 0x100, 0x500, 0x2000 };
  void *keep[5], *tc[3], *fb[9];
  for (int i = 0; i < 5; i++) { keep[i] = malloc(sizes[i]); memset(keep[i], 0x41 + i, sizes[i]); }
  for (int i = 0; i < 3; i++) tc[i] = malloc(0x38);
  for (int i = 0; i < 3; i++) free(tc[i]);
  for (int i = 0; i < 9; i++) fb[i] = malloc(0x28);
  void *big = malloc(0x600);
  void *guard = malloc(0x18);
  void *mm = malloc(0x40000); /* above the mmap threshold */
  memset(mm, 0x5a, 64);
  pthread_t t;
  pthread_barrier_init(&ready, NULL, 2);
  pthread_barrier_init(&never, NULL, 2);
  pthread_create(&t, NULL, worker, NULL);
  pthread_barrier_wait(&ready);
  /* last, so no later malloc reuses them (pthread_create allocates; a large malloc consolidates fastbins) */
  free(big); /* too big for tcache: unsorted bin */
  for (int i = 0; i < 9; i++) free(fb[i]); /* 7 fill tcache[1], 2 go to fastbin[1] */
  printf("{\"keep\":[\"%p\",\"%p\",\"%p\",\"%p\",\"%p\"],\"tc\":[\"%p\",\"%p\",\"%p\"],\"fb\":[\"%p\",\"%p\",\"%p\",\"%p\",\"%p\",\"%p\",\"%p\",\"%p\",\"%p\"],\"big\":\"%p\",\"guard\":\"%p\",\"mm\":\"%p\",\"thr\":[\"%p\",\"%p\",\"%p\",\"%p\"]}\n",
    keep[0], keep[1], keep[2], keep[3], keep[4], tc[0], tc[1], tc[2], fb[0], fb[1], fb[2], fb[3], fb[4], fb[5], fb[6], fb[7], fb[8], big, guard, mm, thr[0], thr[1], thr[2], thr[3]);
  getchar(); /* until the test closes stdin */
  return 0;
}
`;

type Addrs = { keep: string[]; tc: string[]; fb: string[]; big: string; guard: string; mm: string; thr: string[] };
type MapLine = { start: bigint; end: bigint; readable: boolean; writable: boolean; path: string };

function maps(pid: number): MapLine[] {
  return readFileSync(`/proc/${pid}/maps`, "utf8").trim().split("\n").map((l) => {
    const [range, perms, , , , ...rest] = l.split(/\s+/);
    const [s, e] = range.split("-");
    return { start: BigInt(`0x${s}`), end: BigInt(`0x${e}`), readable: perms[0] === "r", writable: perms[1] === "w", path: rest.join(" ") };
  });
}

const hasCc = (() => {
  if (process.platform !== "linux") return false;
  try {
    execFileSync("cc", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe.runIf(hasCc)("glibc heap explorer against a live process", () => {
  let dir = "";
  let child: ChildProcess | null = null;
  let addrs: Addrs;
  let report: HeapReport;
  const A = (s: string) => BigInt(s);

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "echodebug-heap-"));
    writeFileSync(join(dir, "heapdemo.c"), kProgram);
    execFileSync("cc", ["-O0", "-pthread", "-o", join(dir, "heapdemo"), join(dir, "heapdemo.c")], { stdio: "pipe" });
    const proc = spawn(join(dir, "heapdemo"), [], { stdio: ["pipe", "pipe", "inherit"] });
    child = proc;
    const line = await new Promise<string>((resolve, reject) => {
      const rl = createInterface({ input: proc.stdout });
      rl.once("line", resolve);
      proc.once("exit", (c) => reject(new Error(`heapdemo exited with ${c}`)));
    });
    addrs = JSON.parse(line) as Addrs;
    const pid = proc.pid ?? 0;
    const fd = openSync(`/proc/${pid}/mem`, "r");
    try {
      const read = async (a: bigint, n: number) => {
        const b = new Uint8Array(n);
        try {
          return readSync(fd, b, 0, n, a) === n ? b : null;
        } catch {
          return null;
        }
      };
      const ml = maps(pid).filter((m) => m.readable);
      const libcLines = ml.filter((m) => /\/libc[.-][^/]*$/.test(m.path));
      const libc = { name: "libc.so.6", base: libcLines[0].start, size: Number(libcLines[libcLines.length - 1].end - libcLines[0].start) };
      const mem = new HeapMem(read);
      const img = (await mem.bytes(libc.base, Math.min(libc.size, 0x400000))) ?? new Uint8Array();
      const mods = new Map<string, { base: bigint; size: number }>();
      for (const m of ml.filter((x) => x.path.startsWith("/"))) {
        const cur = mods.get(m.path);
        mods.set(m.path, cur ? { base: cur.base, size: Number(m.end - cur.base) } : { base: m.start, size: Number(m.end - m.start) });
      }
      // module images may have holes; scan libc's first pages in one piece for the banner
      let version = glibcVersion(img);
      if (!version) {
        for (const m of libcLines) {
          const b = await read(m.start, Number(m.end - m.start));
          version = b ? glibcVersion(b) : null;
          if (version) break;
        }
      }
      report = await exploreGlibc({ mem, regions: ml.map((m) => ({ base: m.start, size: Number(m.end - m.start), writable: m.writable })), libc, modules: [...mods.values()], version });
    } finally {
      closeSync(fd);
    }
  }, 60_000);

  afterAll(() => {
    child?.stdin?.end();
    child?.kill();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const chunkOf = (user: string) => report.chunks.find((c) => c.user === A(user));

  it("finds main_arena and walks the main heap without errors", () => {
    expect(report.platform).toBe("glibc");
    // the source and notes say how the arena was (not) found, which is what a failure needs
    const why = JSON.stringify({ source: report.source, version: report.version, notes: report.notes, errors: report.errors.slice(0, 5), heaps: report.heaps.map((h) => h.label) });
    expect(report.heaps.find((h) => h.label === "main_arena"), why).toBeTruthy();
    expect(report.errors).toEqual([]);
    expect(report.version).toMatch(/^2\.\d+$/);
  });

  it("finds every live allocation with its size", () => {
    const sizes = [0x18, 0x48, 0x100, 0x500, 0x2000];
    addrs.keep.forEach((u, i) => {
      const c = chunkOf(u);
      expect(c?.state).toBe("in-use");
      expect(c!.userSize).toBeGreaterThanOrEqual(sizes[i]);
      expect(c!.userSize).toBeLessThan(sizes[i] + 0x20);
      expect(c!.preview?.[0]).toBe(0x41 + i);
    });
    expect(findChunk(report.chunks, A(addrs.keep[1]) + 5n)?.user).toBe(A(addrs.keep[1]));
  });

  it("puts freed chunks in their tcache, fastbin and unsorted bins", () => {
    for (const u of addrs.tc) expect(chunkOf(u)?.bin).toBe("tcache[2]");
    for (const u of addrs.fb.slice(0, 7)) expect(chunkOf(u)?.bin).toBe("tcache[1]");
    for (const u of addrs.fb.slice(7)) expect(chunkOf(u)?.bin).toBe("fastbin[1]");
    expect(chunkOf(addrs.big)?.state).toBe("unsorted");
    expect(chunkOf(addrs.guard)?.state).toBe("in-use");
    const t1 = report.bins.find((b) => b.kind === "tcache" && b.index === 1 && b.heap === chunkOf(addrs.fb[0])?.heap);
    expect(t1?.count).toBe(7);
    expect(t1?.error).toBeUndefined();
  });

  it("finds the mmapped chunk", () => {
    const c = chunkOf(addrs.mm);
    expect(c?.state).toBe("mmapped");
    expect(c!.size).toBeGreaterThanOrEqual(0x40000);
  });

  it("walks the thread arena and its tcache", () => {
    const owner = chunkOf(addrs.thr[0])?.heap;
    const arena = report.heaps.find((h) => h.id === owner);
    expect(arena?.label).toMatch(/^arena #/);
    for (const u of addrs.thr.slice(0, 3)) expect(chunkOf(u)?.state).toBe("in-use");
    expect(chunkOf(addrs.thr[3])?.bin).toBe("tcache[7]");
    expect(chunkOf(addrs.thr[3])?.heap).toBe(owner);
  });
});
