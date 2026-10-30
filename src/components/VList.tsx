// virtualized fixed-height list
import { type ReactNode, useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

type Props = { count: number; row: (i: number) => ReactNode; height?: number; className?: string; scrollTo?: number | null };

export default function VList({ count, row, height = 20, className = "vlist", scrollTo }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({ count, getScrollElement: () => ref.current, estimateSize: () => height, overscan: 20 });
  useEffect(() => {
    if (scrollTo != null && scrollTo >= 0) v.scrollToIndex(scrollTo, { align: "center" });
  }, [scrollTo, v]);
  return (
    <div ref={ref} className={className}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((it) => (
          <div key={it.key} style={{ position: "absolute", top: 0, left: 0, right: 0, height, transform: `translateY(${it.start}px)` }}>
            {row(it.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
