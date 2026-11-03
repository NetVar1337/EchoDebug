// What the Structs view is showing right now (published by the view), so the assistant can
// suggest fields from the live sample, and a layout the assistant's accepted fields hand back.
import { create } from "zustand";
import type { Field } from "@/lib/analysis/struct";

type StructCtx = {
  name: string;
  base: string | null;
  fields: Field[];
  data: Uint8Array | null;
  rtti: string;
  /** fields to apply in the Structs view (cleared by the view once applied) */
  pending: Field[] | null;
};

export const useStructCtx = create<StructCtx>(() => ({ name: "", base: null, fields: [], data: null, rtti: "", pending: null }));
