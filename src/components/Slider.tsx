"use client";

import { motion } from "framer-motion";
import { useMemo, type CSSProperties } from "react";

export type SliderColorStop = { value: number; color: string };

type SliderProps = {
  min: number;
  max: number;
  step: number;
  value: number;
  onChange: (value: number) => void;
  colorStops?: SliderColorStop[];
  label?: string;
  valueFormatter?: (v: number) => string;
  disabled?: boolean;
  formatMin?: (v: number) => string;
  formatMax?: (v: number) => string;
  className?: string;
};

function buildTrackGradient(stops: SliderColorStop[]): string {
  const sorted = [...stops].sort((a, b) => a.value - b.value);
  if (sorted.length === 0) return "var(--accent)";
  const parts = sorted.map((s) => `${s.color} ${s.value}%`);
  return `linear-gradient(to right, ${parts.join(", ")})`;
}

export function Slider({
  min,
  max,
  step,
  value,
  onChange,
  colorStops,
  label,
  valueFormatter = (v) => String(v),
  disabled = false,
  formatMin,
  formatMax,
  className = "",
}: SliderProps) {
  const trackBg = useMemo(() => {
    if (!colorStops?.length) return undefined;
    return buildTrackGradient(colorStops);
  }, [colorStops]);

  const minLabel = formatMin ? formatMin(min) : String(min);
  const maxLabel = formatMax ? formatMax(max) : String(max);

  return (
    <div className={`slider-custom ${className}`}>
      <style>{`
        .slider-custom input[type="range"] {
          -webkit-appearance: none;
          appearance: none;
          width: 100%;
          height: 24px;
          background: transparent;
        }
        .slider-custom input[type="range"]:focus-visible {
          outline: none;
        }
        .slider-custom input[type="range"]:focus-visible::-webkit-slider-thumb {
          box-shadow:
            0 0 0 3px var(--background),
            0 0 0 5px var(--accent);
        }
        .slider-custom input[type="range"]:focus-visible::-moz-range-thumb {
          box-shadow:
            0 0 0 3px var(--background),
            0 0 0 5px var(--accent);
        }
        .slider-custom input[type="range"]::-webkit-slider-runnable-track {
          height: 6px;
          border-radius: 9999px;
          background: var(--slider-track-bg, var(--accent));
        }
        .slider-custom input[type="range"]::-webkit-slider-thumb {
          -webkit-appearance: none;
          appearance: none;
          width: 18px;
          height: 18px;
          margin-top: -6px;
          border-radius: 9999px;
          background: var(--accent);
          border: 2px solid white;
          box-shadow: 0 1px 4px color-mix(in srgb, var(--foreground) 28%, transparent);
          cursor: pointer;
          transition: box-shadow 180ms ease, transform 180ms ease;
        }
        .slider-custom input[type="range"]:hover::-webkit-slider-thumb {
          box-shadow: 0 4px 14px color-mix(in srgb, var(--foreground) 38%, transparent);
        }
        .slider-custom input[type="range"]:active::-webkit-slider-thumb {
          transform: scale(1.1);
        }
        .slider-custom input[type="range"]:disabled::-webkit-slider-thumb {
          cursor: not-allowed;
          opacity: 0.45;
        }
        .slider-custom input[type="range"]::-moz-range-track {
          height: 6px;
          border-radius: 9999px;
          background: var(--slider-track-bg, var(--accent));
        }
        .slider-custom input[type="range"]::-moz-range-thumb {
          width: 18px;
          height: 18px;
          border-radius: 9999px;
          background: var(--accent);
          border: 2px solid white;
          box-shadow: 0 1px 4px color-mix(in srgb, var(--foreground) 28%, transparent);
          cursor: pointer;
          transition: box-shadow 180ms ease, transform 180ms ease;
        }
        .slider-custom input[type="range"]:hover::-moz-range-thumb {
          box-shadow: 0 4px 14px color-mix(in srgb, var(--foreground) 38%, transparent);
        }
        .slider-custom input[type="range"]:active::-moz-range-thumb {
          transform: scale(1.1);
        }
        .slider-custom input[type="range"]:disabled::-moz-range-thumb {
          cursor: not-allowed;
          opacity: 0.45;
        }
      `}</style>
      {label ? (
        <span className="mb-2 block text-sm text-(--muted)">{label}</span>
      ) : null}
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className="block w-full"
        style={
          {
            "--slider-track-bg": trackBg ?? "var(--accent)",
          } as CSSProperties
        }
      />
      <div className="mt-2 flex items-baseline justify-between gap-3">
        <span className="shrink-0 font-mono text-xs tabular-nums text-(--muted)">
          {minLabel}
        </span>
        <motion.span
          key={value}
          initial={{ opacity: 0.65, y: 3 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ type: "spring", stiffness: 420, damping: 30 }}
          className="min-w-0 truncate text-center font-mono text-xl font-medium tabular-nums text-(--foreground)"
        >
          {valueFormatter(value)}
        </motion.span>
        <span className="shrink-0 font-mono text-xs tabular-nums text-(--muted)">
          {maxLabel}
        </span>
      </div>
    </div>
  );
}
