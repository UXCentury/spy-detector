import { screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";

import NetworkPage from "@/app/network/page";
import { renderWithFullPageShell } from "@/test-utils/render";

vi.mock("next/navigation", () => ({
  usePathname: () => "/network",
}));

describe("Network page", () => {
  it("shows empty copy when list_network_connections returns no rows", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "list_network_connections") return [];
      return null;
    });

    renderWithFullPageShell(<NetworkPage />);

    await waitFor(() => {
      expect(screen.getByText(/No connections to display/i)).toBeInTheDocument();
    });
  });
});
