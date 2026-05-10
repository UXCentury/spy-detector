import type { HTMLAttributes } from "react";

export function Skeleton({
  className = "",
  ...rest
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`relative overflow-hidden rounded-md bg-(--surface-2) ${className}`}
      {...rest}
    >
      <div
        className="absolute inset-y-0 w-2/5 bg-gradient-to-r from-transparent via-(--border-bright)/30 to-transparent"
        style={{ animation: "shimmer 1.35s ease-in-out infinite" }}
        aria-hidden
      />
    </div>
  );
}
