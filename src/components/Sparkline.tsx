"use client";

import { useMemo } from "react";

type SparklineProps = {
  data: number[];
  height?: number;
  color?: string;
  className?: string;
};

export function Sparkline({
  data,
  height = 40,
  color = "var(--accent-2)",
  className = "",
}: SparklineProps) {
  const path = useMemo(() => {
    if (!data.length) return "";
    const w = 120;
    const pad = 2;
    const min = Math.min(...data);
    const max = Math.max(...data);
    const span = max - min || 1;
    const innerH = height - pad * 2;
    if (data.length === 1) {
      const y = pad + innerH / 2;
      const x1 = pad;
      const x2 = w - pad;
      return `M${x1},${y.toFixed(1)} L${x2},${y.toFixed(1)}`;
    }
    const step = (w - pad * 2) / (data.length - 1);
    return data
      .map((v, i) => {
        const x = pad + i * step;
        const y = pad + (1 - (v - min) / span) * innerH;
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }, [data, height]);

  if (!data.length) {
    return (
      <div
        className={`flex items-center justify-center rounded border border-dashed border-(--border) text-[10px] text-(--muted) ${className}`}
        style={{ height, width: 120 }}
      >
        No data
      </div>
    );
  }

  return (
    <svg
      width={120}
      height={height}
      className={className}
      viewBox={`0 0 120 ${height}`}
      preserveAspectRatio="none"
    >
      <path
        d={path}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
