// One tooltip bubble for the whole app. Any element opts in with data-tip;
// the native `title` attribute is not used because it cannot be styled and
// lags behind the pointer.
import { useEffect, useRef, useState } from "react";

type Placed = { text: string; left: number; top: number };

const kDelayMs = 380;
const kGap = 7;
const kMargin = 6;

export default function TooltipLayer() {
  const [tip, setTip] = useState<Placed | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const bubble = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const cancel = () => {
      clearTimeout(timer.current);
      timer.current = undefined;
      setTip(null);
    };

    const onOver = (e: PointerEvent) => {
      const el = (e.target as HTMLElement | null)?.closest?.("[data-tip]") as HTMLElement | null;
      const text = el?.dataset.tip;
      if (!el || !text) return cancel();
      const r = el.getBoundingClientRect();
      // Place below the element, flip above when there is no room.
      const below = r.bottom + kGap + 24 < window.innerHeight;
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setTip({ text, left: r.left, top: below ? r.bottom + kGap : r.top - kGap }), kDelayMs);
    };

    document.addEventListener("pointerover", onOver, true);
    document.addEventListener("pointerdown", cancel, true);
    document.addEventListener("wheel", cancel, true);
    document.addEventListener("keydown", cancel, true);
    window.addEventListener("blur", cancel);
    return () => {
      document.removeEventListener("pointerover", onOver, true);
      document.removeEventListener("pointerdown", cancel, true);
      document.removeEventListener("wheel", cancel, true);
      document.removeEventListener("keydown", cancel, true);
      window.removeEventListener("blur", cancel);
      clearTimeout(timer.current);
    };
  }, []);

  // Clamp horizontally once the bubble has a measured width.
  useEffect(() => {
    if (!tip || !bubble.current) return;
    const w = bubble.current.offsetWidth;
    const max = window.innerWidth - w - kMargin;
    if (tip.left > max) setTip((t) => (t ? { ...t, left: Math.max(kMargin, max) } : t));
  }, [tip]);

  if (!tip) return null;
  const h = bubble.current?.offsetHeight ?? 0;
  const top = tip.top - h < kMargin ? tip.top + 16 : tip.top;
  return (
    <div ref={bubble} className="tooltip" role="tooltip" style={{ left: tip.left, top }}>
      {tip.text}
    </div>
  );
}
