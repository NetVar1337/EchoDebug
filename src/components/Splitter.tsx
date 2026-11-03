// drag handle that writes a CSS custom property on the app root
import { type RefObject, useState } from "react";
import { useUi } from "@/store/ui";

type Props = { axis: "x" | "y"; variable: string; target: RefObject<HTMLElement | null>; min: number; max: number; invert?: boolean };

export default function Splitter({ axis, variable, target, min, max, invert }: Props) {
  const [dragging, setDragging] = useState(false);
  const onDown = (e: React.PointerEvent) => {
    const el = target.current;
    if (!el) return;
    const start = axis === "x" ? e.clientX : e.clientY;
    const prev = (e.currentTarget as HTMLElement).previousElementSibling as HTMLElement | null;
    const next = (e.currentTarget as HTMLElement).nextElementSibling as HTMLElement | null;
    const sized = invert ? next : prev;
    const initial = sized ? (axis === "x" ? sized.getBoundingClientRect().width : sized.getBoundingClientRect().height) : min;
    setDragging(true);
    const move = (ev: PointerEvent) => {
      const delta = (axis === "x" ? ev.clientX : ev.clientY) - start;
      const v = Math.max(min, Math.min(max, initial + (invert ? -delta : delta)));
      el.style.setProperty(variable, `${v}px`);
    };
    const up = () => {
      setDragging(false);
      const v = el.style.getPropertyValue(variable);
      if (v) useUi.getState().set({ layout: { ...useUi.getState().layout, [variable]: v } });
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };
  return <div className="splitter" data-axis={axis} data-dragging={dragging} onPointerDown={onDown} role="separator" aria-orientation={axis === "x" ? "vertical" : "horizontal"} />;
}
