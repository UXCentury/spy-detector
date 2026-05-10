"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { severityTier, tierColorVar } from "@/lib/thresholds";

type Size = "sm" | "md" | "lg";

const sizeMap: Record<
  Size,
  { dim: number; stroke: number; r: number; font: string }
> = {
  sm: { dim: 32, stroke: 3, r: 12, font: "text-[9px]" },
  md: { dim: 64, stroke: 4, r: 26, font: "text-xs" },
  lg: { dim: 128, stroke: 6, r: 54, font: "text-lg" },
};

type ScoreGaugeProps = {
  score: number;
  warnThreshold: number;
  alertThreshold: number;
  size?: Size;
  className?: string;
  animate?: boolean;
};

export function ScoreGauge({
  score,
  warnThreshold,
  alertThreshold,
  size = "md",
  className = "",
  animate = true,
}: ScoreGaugeProps) {
  const { dim, stroke, r, font } = sizeMap[size];
  const c = dim / 2;
  const circ = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, score));
  const posRef = useRef(0);
  const [animatedDisplay, setAnimatedDisplay] = useState(() =>
    animate ? 0 : clamped,
  );

  useLayoutEffect(() => {
    if (!animate) {
      posRef.current = clamped;
    }
  }, [animate, clamped]);

  useEffect(() => {
    if (!animate) return;
    const from = posRef.current;
    let raf = 0;
    const start = performance.now();
    const duration = 420;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / duration);
      const eased = 1 - (1 - p) ** 3;
      const v = Math.round(from + (clamped - from) * eased);
      posRef.current = v;
      setAnimatedDisplay(v);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [clamped, animate]);

  const display = animate ? animatedDisplay : clamped;

  const tier = severityTier(display, warnThreshold, alertThreshold);
  const color = tierColorVar(tier);
  const dash = useMemo(
    () => circ * (1 - display / 100),
    [circ, display],
  );

  return (
    <div
      className={`relative shrink-0 ${className}`}
      style={{ width: dim, height: dim }}
    >
      <svg width={dim} height={dim} className="-rotate-90">
        <circle
          cx={c}
          cy={c}
          r={r}
          fill="none"
          stroke="var(--border)"
          strokeWidth={stroke}
        />
        <circle
          cx={c}
          cy={c}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={dash}
          style={{ transition: "stroke-dashoffset 0.2s ease, stroke 0.2s ease" }}
        />
      </svg>
      <span
        className={`absolute inset-0 flex items-center justify-center font-medium tabular-nums ${font}`}
        style={{ color }}
      >
        {display}
      </span>
    </div>
  );
}
