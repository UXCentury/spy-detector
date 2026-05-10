import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  normalizePagePath,
  PageStatusProvider,
  usePageReady,
  usePageStatus,
} from "@/lib/PageStatus";

vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
}));

function ReadyCaller({ ready }: { ready: boolean }) {
  usePageReady(ready);
  return null;
}

function ReadyIndicator() {
  const { readyPath } = usePageStatus();
  return <span data-testid="ready-path">{readyPath ?? "pending"}</span>;
}

describe("normalizePagePath", () => {
  it("strips trailing slash except root", () => {
    expect(normalizePagePath("/foo/")).toBe("/foo");
    expect(normalizePagePath("/")).toBe("/");
  });
});

describe("PageStatusProvider + usePageReady", () => {
  it("updates readyPath when the active route reports ready", async () => {
    const { rerender } = render(
      <PageStatusProvider>
        <ReadyCaller ready={false} />
        <ReadyIndicator />
      </PageStatusProvider>,
    );

    expect(screen.getByTestId("ready-path")).toHaveTextContent("pending");

    rerender(
      <PageStatusProvider>
        <ReadyCaller ready />
        <ReadyIndicator />
      </PageStatusProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("ready-path")).toHaveTextContent("/dashboard");
    });
  });
});
