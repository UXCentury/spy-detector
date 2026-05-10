import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { Slider } from "@/components/Slider";

/**
 * jsdom does not implement stepped keyboard navigation for range inputs the way
 * Chromium does, so we assert the handler via change events (same path as real input updates).
 */
function ControlledSlider(props: {
  min: number;
  max: number;
  step: number;
  initial: number;
}) {
  const [v, setV] = useState(props.initial);
  return (
    <div>
      <Slider
        min={props.min}
        max={props.max}
        step={props.step}
        value={v}
        onChange={setV}
        label="Units"
      />
      <span data-testid="val">{v}</span>
    </div>
  );
}

describe("Slider", () => {
  it("emits onChange with the new numeric value when the range changes", () => {
    const onChange = vi.fn();

    render(
      <Slider min={0} max={100} step={5} value={50} onChange={onChange} />,
    );

    const input = screen.getByRole("slider");
    fireEvent.change(input, { target: { value: "60" } });
    expect(onChange).toHaveBeenCalledWith(60);
  });

  it("round-trips controlled state through onChange", () => {
    render(<ControlledSlider min={10} max={40} step={5} initial={20} />);

    const input = screen.getByRole("slider");
    expect(screen.getByTestId("val")).toHaveTextContent("20");

    fireEvent.change(input, { target: { value: "25" } });
    expect(screen.getByTestId("val")).toHaveTextContent("25");
  });
});
