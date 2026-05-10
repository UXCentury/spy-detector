"use client";

import { motion } from "framer-motion";

type ToggleTone = "default" | "danger";

type ToggleProps = {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  description?: string;
  disabled?: boolean;
  tone?: ToggleTone;
  title?: string;
  ariaLabel?: string;
  /** Smaller track + thumb for dense layouts (e.g. overview rows). */
  compact?: boolean;
};

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  tone = "default",
  title: titleAttr,
  ariaLabel,
  compact = false,
}: ToggleProps) {
  const onColor =
    tone === "danger" ? "var(--severity-high)" : "var(--accent)";
  const offTrack = "var(--border-bright)";
  const hasLabel = Boolean(label);
  const trackClass = compact
    ? `${hasLabel ? "mt-0.5 " : ""}inline-flex h-4 w-7 shrink-0`
    : `${hasLabel ? "mt-0.5 " : ""}inline-flex h-5 w-9 shrink-0`;
  const thumbClass = compact ? "size-3" : "size-4";
  const thumbX = compact
    ? checked
      ? 12
      : 0
    : checked
      ? 16
      : 0;

  const switchTrack = (
    <span className={`relative ${trackClass} items-center rounded-full p-0.5`}>
      <span
        className="absolute inset-0 rounded-full transition-colors duration-150"
        style={{ backgroundColor: checked ? onColor : offTrack }}
      />
      <motion.span
        layout
        className={`relative z-10 block ${thumbClass} rounded-full bg-white shadow-sm`}
        initial={false}
        animate={{ x: thumbX }}
        transition={{ type: "spring", stiffness: 520, damping: 34 }}
        style={{ marginLeft: compact ? 1 : 2 }}
      />
    </span>
  );

  if (!hasLabel) {
    return (
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabel}
        disabled={disabled}
        title={titleAttr}
        onClick={() => !disabled && onChange(!checked)}
        className="inline-flex cursor-pointer items-center rounded-full transition-opacity duration-150 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {switchTrack}
      </button>
    );
  }

  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      title={titleAttr}
      onClick={() => !disabled && onChange(!checked)}
      className="flex w-full cursor-pointer items-start gap-4 rounded-xl border border-transparent p-1 text-left transition-colors duration-150 hover:border-(--border)/80 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-transparent"
    >
      <div className="min-w-0 flex-1 pt-0.5">
        <div className="text-sm font-medium text-(--foreground)">{label}</div>
        {description ? (
          <p className="mt-1 text-xs leading-relaxed text-(--muted)">
            {description}
          </p>
        ) : null}
      </div>
      {switchTrack}
    </button>
  );
}
