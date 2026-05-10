"use client";

import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";

type Counts = { low: number; warn: number; high: number };

type SeverityDonutProps = {
  counts: Counts;
  className?: string;
  centerValue?: number;
};

type Slice = { name: string; value: number; fill: string };

export function SeverityDonut({
  counts,
  className = "",
  centerValue,
}: SeverityDonutProps) {
  const total = counts.low + counts.warn + counts.high;
  const data: Slice[] =
    total === 0
      ? [{ name: "none", value: 1, fill: "var(--border)" }]
      : [
          ...(counts.high > 0
            ? [{ name: "high", value: counts.high, fill: "var(--severity-high)" }]
            : []),
          ...(counts.warn > 0
            ? [{ name: "warn", value: counts.warn, fill: "var(--severity-warn)" }]
            : []),
          ...(counts.low > 0
            ? [{ name: "low", value: counts.low, fill: "var(--severity-low)" }]
            : []),
        ];

  const center = centerValue !== undefined ? centerValue : total;

  return (
    <div className={`flex flex-col items-center gap-3 ${className}`}>
      <div className="relative h-40 w-40 shrink-0">
        <ResponsiveContainer width={160} height={160}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius="72%"
              outerRadius="100%"
              startAngle={90}
              endAngle={-270}
              stroke="none"
              isAnimationActive
              animationDuration={500}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.fill} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-(--foreground)">
            {center}
          </span>
          <span className="text-[10px] uppercase tracking-wide text-(--muted)">
            findings
          </span>
        </div>
      </div>
      <div className="flex flex-wrap justify-center gap-3 text-[10px] text-(--muted)">
        <span className="flex items-center gap-1">
          <span
            className="size-2 rounded-full"
            style={{ background: "var(--severity-low)" }}
          />
          Low {counts.low}
        </span>
        <span className="flex items-center gap-1">
          <span
            className="size-2 rounded-full"
            style={{ background: "var(--severity-warn)" }}
          />
          Warn {counts.warn}
        </span>
        <span className="flex items-center gap-1">
          <span
            className="size-2 rounded-full"
            style={{ background: "var(--severity-high)" }}
          />
          High {counts.high}
        </span>
      </div>
    </div>
  );
}
