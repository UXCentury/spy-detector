"use client";

export function PulseDot({
  color = "var(--accent-2)",
  className = "",
}: {
  color?: string;
  className?: string;
}) {
  return (
    <span
      className={`inline-block size-2 shrink-0 rounded-full ${className}`}
      style={{
        backgroundColor: color,
        animation: "pulse-dot 1.6s ease-in-out infinite",
      }}
      aria-hidden
    />
  );
}
