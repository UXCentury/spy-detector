import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider, useToast } from "@/components/Toast";

function Trigger() {
  const { showToast } = useToast();
  return (
    <button type="button" onClick={() => showToast("Saved")}>
      Go
    </button>
  );
}

describe("ToastProvider", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("mounts a toast via showToast then removes it after the timeout", async () => {
    const user = userEvent.setup({
      advanceTimers: vi.advanceTimersByTime.bind(vi),
    });

    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /^go$/i }));
    expect(await screen.findByText("Saved")).toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(4300);

    await waitFor(() =>
      expect(screen.queryByText("Saved")).not.toBeInTheDocument(),
    );
  });
});
