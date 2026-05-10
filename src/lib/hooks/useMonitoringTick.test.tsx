import { renderHook, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";

import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import { SAMPLE_MONITORING_TICK } from "@/test-utils/fixtures/monitoringTick";
import { tauriListenBridge } from "@/test-utils/tauriListenBridge";

describe("useMonitoringTick", () => {
  it("loads initial tick via invoke then updates on monitoring_tick events", async () => {
    const initial = { ...SAMPLE_MONITORING_TICK, processCount: 7 };
    const updated = { ...SAMPLE_MONITORING_TICK, processCount: 200 };
    vi.mocked(invoke).mockResolvedValue(initial);

    const { result } = renderHook(() => useMonitoringTick());

    await waitFor(() =>
      expect(result.current.tick?.processCount).toBe(7),
    );

    tauriListenBridge.emit("monitoring_tick", updated);

    await waitFor(() =>
      expect(result.current.tick?.processCount).toBe(200),
    );
  });
});
