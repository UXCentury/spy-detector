"use client";

import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { OverviewDashboard } from "@/components/overview/OverviewDashboard";
import { usePageReady } from "@/lib/PageStatus";
import type { Finding } from "@/lib/types";

export default function OverviewPage() {
  const [scanPrimed, setScanPrimed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void invoke<Finding[] | null>("get_latest_findings")
      .then(() => {
        if (!cancelled) setScanPrimed(true);
      })
      .catch(() => {
        if (!cancelled) setScanPrimed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  usePageReady(scanPrimed);

  return <OverviewDashboard />;
}
