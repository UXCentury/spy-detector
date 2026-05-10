import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";

import ProcessesPage from "@/app/processes/page";
import { SAMPLE_MONITORING_TICK } from "@/test-utils/fixtures/monitoringTick";
import { renderWithFullPageShell } from "@/test-utils/render";

vi.mock("next/navigation", () => ({
  usePathname: () => "/processes",
}));

function stubProcessesInvokes() {
  vi.mocked(invoke).mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case "list_processes":
        return [];
      case "get_latest_findings":
        return [];
      case "get_app_settings":
        return { warnThreshold: 50, alertThreshold: 75 };
      case "get_monitoring_tick":
        return SAMPLE_MONITORING_TICK;
      default:
        return null;
    }
  });
}

describe("Processes page", () => {
  it('toggles the "Show ignored" filter chip', async () => {
    const user = userEvent.setup();
    stubProcessesInvokes();

    renderWithFullPageShell(<ProcessesPage />);

    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: /scan results/i }),
      ).toBeInTheDocument();
    });

    const chip = screen.getByRole("switch", { name: /show ignored/i });
    expect(chip).toHaveAttribute("aria-checked", "false");

    await user.click(chip);
    expect(chip).toHaveAttribute("aria-checked", "true");

    await user.click(chip);
    expect(chip).toHaveAttribute("aria-checked", "false");
  });
});
