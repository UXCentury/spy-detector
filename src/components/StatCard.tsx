"use client";

import type { LucideIcon } from "lucide-react";
import { AnimatedNumber } from "@/components/AnimatedNumber";

type StatCardProps = {
  icon: LucideIcon;
  label: string;
  value: number;
  delta?: { value: number; label: string };
  className?: string;
};

export function StatCard({
  icon: Icon,
  label,
  value,
  delta,
  className = "",
}: StatCardProps) {
  return (
    <div
      className={`rounded-xl border border-(--border) bg-(--surface)/80 p-4 shadow-sm backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2)/60 ${className}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="rounded-lg border border-(--border) bg-(--surface-2)/80 p-2 text-(--accent)">
          <Icon className="size-4" aria-hidden />
        </div>
        {delta ? (
          <span
            className={`text-xs tabular-nums ${
              delta.value > 0
                ? "text-(--severity-warn)"
                : delta.value < 0
                  ? "text-(--severity-low)"
                  : "text-(--muted)"
            }`}
          >
            {delta.value > 0 ? "+" : ""}
            {delta.value} {delta.label}
          </span>
        ) : null}
      </div>
      <div className="mt-3 text-2xl font-semibold tabular-nums tracking-tight text-(--foreground)">
        <AnimatedNumber value={value} />
      </div>
      <div className="mt-1 text-xs font-medium text-(--muted)">{label}</div>
    </div>
  );
}
