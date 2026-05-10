import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { OverviewDashboard } from "@/components/overview/OverviewDashboard";
import { SAMPLE_MONITORING_TICK } from "@/test-utils/fixtures/monitoringTick";
import { renderWithLangAndToast } from "@/test-utils/render";

vi.mock("@/lib/hooks/useMonitoringTick", () => ({
  useMonitoringTick: () => ({
    tick: {
      ...SAMPLE_MONITORING_TICK,
      etwProcessActive: true,
      elevated: true,
    },
  }),
}));

vi.mock("@/lib/hooks/useScanInterval", () => ({
  useScanInterval: () => ({ seconds: 3600 }),
}));

vi.mock("@/lib/hooks/useScanCompleted", () => ({
  useScanCompleted: () => {},
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
}));

describe("OverviewDashboard Process ETW", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_app_settings") {
        return {
          warnThreshold: 50,
          alertThreshold: 75,
          disabledSignatureTokens: [],
          processEtwEnabled: false,
        };
      }
      if (cmd === "get_runtime_status") return { elevated: true };
      if (cmd === "list_ioc_entries") return [];
      if (cmd === "get_latest_findings") return [];
      if (cmd === "get_scan_history") return [];
      if (cmd === "set_app_settings") return undefined;
      return null;
    });
  });

  it("shows BETA chip; enabling opens confirm; Cancel skips set_app_settings; Confirm enables", async () => {
    const user = userEvent.setup();
    renderWithLangAndToast(<OverviewDashboard />);

    await waitFor(() => {
      expect(screen.getByText("Process ETW")).toBeInTheDocument();
    });

    expect(screen.getByText("BETA")).toBeInTheDocument();

    const toggle = screen.getByRole("switch", {
      name: /Enable or disable Process ETW monitoring/i,
    });
    await user.click(toggle);

    expect(
      await screen.findByRole("dialog", {
        name: /Enable Process ETW \(Beta\)/i,
      }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Cancel$/i }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    const setCallsBefore = vi.mocked(invoke).mock.calls.filter(
      (c) => c[0] === "set_app_settings",
    );
    expect(setCallsBefore).toHaveLength(0);

    await user.click(toggle);
    await screen.findByRole("dialog");
    await user.click(screen.getByRole("button", { name: /Enable Beta Monitor/i }));

    await waitFor(() => {
      const calls = vi.mocked(invoke).mock.calls.filter(
        (c) => c[0] === "set_app_settings",
      );
      expect(calls.length).toBeGreaterThanOrEqual(1);
      const last = calls[calls.length - 1];
      const payload = last[1] as { value: { processEtwEnabled?: boolean } };
      expect(payload.value.processEtwEnabled).toBe(true);
    });
  });
});
