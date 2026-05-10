import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { Toggle } from "@/components/Toggle";

describe("Toggle", () => {
  it("toggles checked state and exposes aria-checked", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    const { rerender } = render(
      <Toggle checked={false} onChange={onChange} ariaLabel="Airplane mode" />,
    );

    const sw = screen.getByRole("switch", { name: /airplane mode/i });
    expect(sw).toHaveAttribute("aria-checked", "false");

    await user.click(sw);
    expect(onChange).toHaveBeenCalledWith(true);

    rerender(<Toggle checked onChange={onChange} ariaLabel="Airplane mode" />);
    expect(sw).toHaveAttribute("aria-checked", "true");
  });

  it("does not call onChange while disabled", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <Toggle checked={false} onChange={onChange} disabled ariaLabel="Locked" />,
    );

    const sw = screen.getByRole("switch", { name: /locked/i });
    await user.click(sw);
    expect(onChange).not.toHaveBeenCalled();
    expect(sw).toBeDisabled();
  });

  it("associates switch role with visible label text", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <Toggle
        checked={false}
        onChange={onChange}
        label="Enable widgets"
        description="Optional detail"
      />,
    );

    const sw = screen.getByRole("switch", { name: /enable widgets/i });
    await user.click(sw);
    expect(onChange).toHaveBeenCalledWith(true);
  });
});
