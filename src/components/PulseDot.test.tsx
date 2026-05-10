import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PulseDot } from "@/components/PulseDot";

describe("PulseDot", () => {
  it("applies the requested colour to the dot", () => {
    const { container } = render(<PulseDot color="rgb(255, 0, 0)" />);
    const dot = container.firstElementChild as HTMLElement;
    expect(dot.style.backgroundColor).toBe("rgb(255, 0, 0)");
  });
});
