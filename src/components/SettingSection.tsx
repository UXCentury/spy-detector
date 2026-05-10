"use client";

import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

type SettingSectionProps = {
  id?: string;
  icon: LucideIcon;
  title: string;
  description?: string;
  children: ReactNode;
  className?: string;
};

export function SettingSection({
  id,
  icon: Icon,
  title,
  description,
  children,
  className = "",
}: SettingSectionProps) {
  return (
    <section
      id={id}
      className={`rounded-xl border border-(--border) bg-(--surface)/70 p-6 backdrop-blur-md ${className}`}
    >
      <header className="mb-5 flex gap-4">
        <div
          className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-(--glow-accent) text-(--accent)"
          aria-hidden
        >
          <Icon className="size-5" strokeWidth={2} />
        </div>
        <div className="min-w-0 space-y-1">
          <h2 className="text-base font-semibold tracking-tight text-(--foreground)">
            {title}
          </h2>
          {description ? (
            <p className="text-sm leading-relaxed text-(--muted)">{description}</p>
          ) : null}
        </div>
      </header>
      <div className="space-y-5">{children}</div>
    </section>
  );
}
