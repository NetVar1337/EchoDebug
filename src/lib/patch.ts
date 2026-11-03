// Every byte EchoDebug writes goes through here so the Patches journal can revert it.
import { request } from "./client";
import { bytesToHex, fmtAddr } from "./hex";
import { readBytes } from "./memory";
import { usePatches } from "@/store/patches";
import { attempt, log } from "@/store/output";

export async function writeJournaled(addr: bigint, data: Uint8Array | string, note: string): Promise<boolean> {
  const hex = typeof data === "string" ? data.toLowerCase() : bytesToHex(data);
  if (!hex || hex.length % 2) return false;
  const before = await attempt("write", readBytes(addr, hex.length / 2));
  if (!before) {
    log("error", "write", `could not read the current bytes at ${fmtAddr(addr)}`);
    return false;
  }
  const ok = await attempt("write", request("write", { address: fmtAddr(addr), data: hex }));
  if (!ok) return false;
  usePatches.getState().add({
    id: Math.random().toString(36).slice(2, 10),
    address: fmtAddr(addr),
    written: hex,
    before: bytesToHex(before),
    note,
    created: Date.now(),
    reverted: false,
  });
  return true;
}
