import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";

import type { MonitoringTick } from "@/lib/types/monitoring";

import { useTauriEvent } from "./useTauriEvent";

export function useMonitoringTick(): {
  tick: MonitoringTick | null;
  refresh: () => Promise<void>;
} {
  const [tick, setTick] = useState<MonitoringTick | null>(null);

  const refresh = useCallback(async () => {
    const next = await invoke<MonitoringTick>("get_monitoring_tick");
    setTick(next);
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => void refresh());
  }, [refresh]);

  useTauriEvent<MonitoringTick>("monitoring_tick", (e) => {
    setTick(e.payload);
  });

  return { tick, refresh };
}
