import { screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";

import OverviewPage from "@/app/page";
import { usePageStatus } from "@/lib/PageStatus";
import { SAMPLE_MONITORING_TICK } from "@/test-utils/fixtures/monitoringTick";
import { renderWithFullPageShell } from "@/test-utils/render";

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
}));

function OverviewReadyProbe() {
  const { readyPath } = usePageStatus();
  return <span data-testid="overview-ready">{readyPath ?? "pending"}</span>;
}

function stubOverviewInvokes() {
  vi.mocked(invoke).mockImplementation(async (cmd: string) => {
    await new Promise((r) => setTimeout(r, 40));
    switch (cmd) {
      case "get_latest_findings":
        return [];
      case "get_runtime_status":
        return { elevated: true };
      case "get_app_settings":
        return {
          warnThreshold: 50,
          alertThreshold: 75,
          disabledSignatureTokens: [],
        };
      case "list_ioc_entries":
        return [];
      case "get_scan_history":
        return [];
      case "get_scan_interval":
        return 3600;
      case "get_monitoring_tick":
        return SAMPLE_MONITORING_TICK;
      default:
        return null;
    }
  });
}

describe("Overview page", () => {
  it("shows loading skeletons then overview title after IPC resolves", async () => {
    stubOverviewInvokes();

    renderWithFullPageShell(
      <>
        <OverviewReadyProbe />
        <OverviewPage />
      </>,
    );

    await waitFor(() => {
      expect(document.querySelector('[class*="rounded-2xl"]')).toBeTruthy();
    });

    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: /^overview$/i }),
      ).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByTestId("overview-ready")).toHaveTextContent("/");
    });
  });
});
