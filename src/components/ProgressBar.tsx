"use client";

export function ProgressBar({ className = "" }: { className?: string }) {
  return (
    <div
      className={`h-1 w-full overflow-hidden rounded-full bg-(--surface-2) ${className}`}
      role="progressbar"
      aria-label="Loading"
    >
      <div
        className="h-full w-1/3 rounded-full bg-(--accent)"
        style={{
          animation: "progress-indeterminate 1.1s ease-in-out infinite",
        }}
      />
    </div>
  );
}
