import { screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";

import { IocCatalogBanner } from "@/components/IocCatalogBanner";
import { renderWithProviders } from "@/test-utils/render";

describe("IocCatalogBanner", () => {
  it("renders upstream URL and active source labels from invoke metadata", async () => {
    vi.mocked(invoke).mockResolvedValue({
      upstreamUrl: "https://example.invalid/ioc.json",
      upstreamSource: "downloaded",
      lastRefreshedAt: null,
    });

    renderWithProviders(<IocCatalogBanner />);

    await waitFor(() =>
      expect(
        screen.getByRole("link", { name: "https://example.invalid/ioc.json" }),
      ).toBeInTheDocument(),
    );

    expect(screen.getByText("Downloaded user IOC")).toBeInTheDocument();
    expect(screen.getByText("never")).toBeInTheDocument();
  });
});
