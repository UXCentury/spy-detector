import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StickyTable } from "../StickyTable";

describe("StickyTable", () => {
  it("renders children", () => {
    render(
      <StickyTable>
        <table data-testid="inner">
          <tbody>
            <tr>
              <td>x</td>
            </tr>
          </tbody>
        </table>
      </StickyTable>,
    );
    expect(screen.getByTestId("inner")).toBeInTheDocument();
  });

  it("applies has-overflow-right when scrolled content extends past viewport", () => {
    render(
      <StickyTable>
        <table>
          <tbody>
            <tr>
              <td>cell</td>
            </tr>
          </tbody>
        </table>
      </StickyTable>,
    );
    const wrap = screen.getByTestId("sticky-table-wrap");
    Object.defineProperty(wrap, "scrollWidth", { value: 500, configurable: true });
    Object.defineProperty(wrap, "clientWidth", { value: 200, configurable: true });
    Object.defineProperty(wrap, "scrollLeft", { value: 0, writable: true, configurable: true });
    fireEvent.scroll(wrap);
    expect(wrap.classList.contains("has-overflow-right")).toBe(true);
  });

  it("applies has-overflow-left when scrolled away from start", () => {
    render(
      <StickyTable>
        <table>
          <tbody>
            <tr>
              <td>cell</td>
            </tr>
          </tbody>
        </table>
      </StickyTable>,
    );
    const wrap = screen.getByTestId("sticky-table-wrap");
    Object.defineProperty(wrap, "scrollWidth", { value: 500, configurable: true });
    Object.defineProperty(wrap, "clientWidth", { value: 200, configurable: true });
    wrap.scrollLeft = 40;
    fireEvent.scroll(wrap);
    expect(wrap.classList.contains("has-overflow-left")).toBe(true);
  });
});
