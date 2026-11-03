// Struct-aware snapshot diff (#7): instead of showing raw changed bytes, map both snapshots
// through a Structs type and report which fields changed, with decoded before/after values.
import { layout, fieldValue, type Field } from "./analysis/struct";

export type FieldChange = {
  name: string;
  offset: number;
  type: Field["type"];
  before: string;
  after: string;
};

export type StructDiff = {
  changed: FieldChange[];
  /** raw byte ranges that changed outside any declared field */
  unmapped: { offset: number; length: number }[];
  unchanged: number;
};

/**
 * Field-level diff of `a` vs `b` under the given field list. Bytes are indexed from the start of
 * the captured window. Fields beyond the shorter buffer are treated as changed to "<short>".
 */
export function diffStruct(fields: readonly Field[], a: Uint8Array, b: Uint8Array): StructDiff {
  const lay = layout(fields);
  const changed: FieldChange[] = [];
  let unchanged = 0;
  const covered = new Set<number>();
  for (let i = 0; i < fields.length; i++) {
    const { offset, size } = lay[i];
    for (let k = 0; k < size; k++) covered.add(offset + k);
    const ba = offset + size <= a.length ? fieldValue(a, offset, fields[i].type) : "<short>";
    const bb = offset + size <= b.length ? fieldValue(b, offset, fields[i].type) : "<short>";
    if (ba !== bb) changed.push({ name: fields[i].name, offset, type: fields[i].type, before: ba, after: bb });
    else unchanged++;
  }
  // unmapped changed bytes
  const unmapped: { offset: number; length: number }[] = [];
  const n = Math.min(a.length, b.length);
  let run = -1;
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i] && !covered.has(i)) {
      if (run < 0) run = i;
    } else if (run >= 0) {
      unmapped.push({ offset: run, length: i - run });
      run = -1;
    }
  }
  if (run >= 0) unmapped.push({ offset: run, length: n - run });
  if (a.length !== b.length) unmapped.push({ offset: n, length: Math.abs(a.length - b.length) });
  return { changed, unmapped, unchanged };
}
