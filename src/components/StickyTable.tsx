"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

function readOverflow(el: HTMLElement) {
  const { scrollLeft, scrollWidth, clientWidth } = el;
  const epsilon = 1;
  return {
    overflowLeft: scrollLeft > epsilon,
    overflowRight: scrollLeft + clientWidth < scrollWidth - epsilon,
  };
}

export function StickyTable({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [overflowLeft, setOverflowLeft] = useState(false);
  const [overflowRight, setOverflowRight] = useState(false);

  const sync = useCallback(() => {
    const el = wrapRef.current;
    if (!el) return;
    const { overflowLeft: ol, overflowRight: or } = readOverflow(el);
    setOverflowLeft(ol);
    setOverflowRight(or);
  }, []);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    sync();
    el.addEventListener("scroll", sync, { passive: true });
    const ro = new ResizeObserver(sync);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", sync);
      ro.disconnect();
    };
  }, [sync]);

  const wrapClass = [
    "sticky-table-wrap",
    overflowLeft ? "has-overflow-left" : "",
    overflowRight ? "has-overflow-right" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div ref={wrapRef} className={wrapClass} data-testid="sticky-table-wrap">
      {children}
    </div>
  );
}

export function TruncCell({
  value,
  title: titleProp,
  className,
}: {
  value: string | null | undefined;
  title?: string;
  className?: string;
}) {
  const v = value ?? "";
  const tip = titleProp ?? v;
  return (
    <td className={`cell-truncate ${className ?? ""}`} title={tip || undefined}>
      <span>{v || "—"}</span>
    </td>
  );
}
