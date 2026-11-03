// Motion preference: on / auto (follow the OS) / off.
// Applied to <html data-motion> so the stylesheet can shorten every animation
// and transition at once (see styles/app.css).
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type MotionPref = "on" | "auto" | "off";

export const kMotionPrefs: { id: MotionPref; label: string; hint: string }[] = [
  { id: "on", label: "On", hint: "always animate" },
  { id: "auto", label: "Auto", hint: "follow the system setting" },
  { id: "off", label: "Off", hint: "no animations" },
];

export function osPrefersReduced(): boolean {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
}

type MotionStore = {
  pref: MotionPref;
  setPref: (p: MotionPref) => void;
};

export const useMotion = create<MotionStore>()(
  persist(
    (set) => ({ pref: "auto", setPref: (pref) => set({ pref }) }),
    { name: "echodebug.motion" },
  ),
);

/**
 * Writes the effective motion mode onto <html>. "auto" resolves to the OS
 * preference, so the stylesheet's `html:not([data-motion="on"])` rule can be
 * scoped by prefers-reduced-motion alone.
 */
export function applyMotion(pref: MotionPref): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.motion = pref === "auto" ? (osPrefersReduced() ? "off" : "on") : pref;
}
