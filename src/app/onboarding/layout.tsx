"use client";

import type { ReactNode } from "react";
import { MinimalWindowHeader } from "@/components/MinimalWindowHeader";

export default function OnboardingLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-dvh flex-col overflow-hidden bg-(--background)">
      <MinimalWindowHeader subtitle="Setup" />
      <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
    </div>
  );
}
