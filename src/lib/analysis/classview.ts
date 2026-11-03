// Class cross-view (#22): joins the static RTTI inventory (what the class is, which vftables exist)
// with a live resolved object (what the vtable pointer and slots actually point at right now) into
// one overview — the panel behind "rebuild class".
import type { RttiClass, RttiInventory } from "./rtti";
import type { VObject, VSlot } from "./vtable";

export type ClassSlot = {
  index: number;
  slotAddress: string;
  target: string;
  module: string;
  offset: string;
  valid: boolean;
  /** live-only: the slot's current value differed from the on-disk expectation */
  hooked?: boolean;
};

export type ClassView = {
  name: string;
  mangled: string;
  base: string;
  /** RTTI type-descriptor address */
  typeDescriptor: string;
  /** vftables found on disk for this class */
  vftables: RttiClass["vftables"];
  /** live object resolution, when one was made */
  live: {
    object: string;
    vtable: string;
    className: string;
    baseName: string;
    slots: ClassSlot[];
  } | null;
};

/** All classes of an inventory as views (no live object). */
export function listClasses(inv: RttiInventory): ClassView[] {
  return inv.classes.map((c) => classView(inv, c.name) ?? { name: c.name, mangled: c.mangled, base: c.base, typeDescriptor: c.address, vftables: c.vftables, live: null });
}

/** One class by (case-insensitive) name, optionally with its live object resolution. */
export function classView(inv: RttiInventory, name: string, live?: VObject | null): ClassView | null {
  const cls = inv.classes.find((c) => c.name.toLowerCase() === name.toLowerCase());
  if (!cls) return null;
  return {
    name: cls.name,
    mangled: cls.mangled,
    base: cls.base,
    typeDescriptor: cls.address,
    vftables: cls.vftables,
    live: live
      ? {
          object: live.object,
          vtable: live.vtable,
          className: live.className,
          baseName: live.baseName,
          slots: live.slots.map((s: VSlot) => ({ index: s.index, slotAddress: s.slotAddress, target: s.target, module: s.module, offset: s.offset, valid: s.valid })),
        }
      : null,
  };
}

/**
 * Marks live slots whose target leaves every vftable recorded on disk for the class as `hooked`
 * (a patched vtable slot) — the difference between "class layout" and "class as it runs".
 */
export function diffLiveAgainstRtti(view: ClassView): ClassView {
  if (!view.live) return view;
  const vftableAddrs = new Set(view.vftables.map((v) => v.address.toLowerCase()));
  const slots = view.live.slots.map((s) => ({
    ...s,
    hooked: s.valid && !vftableAddrs.has(s.target.toLowerCase()) && !vftableAddrs.has(s.slotAddress.toLowerCase()) ? true : s.hooked,
  }));
  return { ...view, live: { ...view.live, slots } };
}
