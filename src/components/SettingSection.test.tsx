import { render, screen, within } from "@testing-library/react";
import { Bell } from "lucide-react";
import { describe, expect, it } from "vitest";

import { SettingSection } from "@/components/SettingSection";

describe("SettingSection", () => {
  it("renders title, optional description, and children", () => {
    render(
      <SettingSection
        icon={Bell}
        title="Alerts"
        description="Choose how you are notified."
      >
        <p>Child content</p>
      </SettingSection>,
    );

    const heading = screen.getByRole("heading", { level: 2, name: "Alerts" });
    const root = heading.closest("section");
    expect(root).toBeTruthy();
    expect(
      within(root as HTMLElement).getByText("Choose how you are notified."),
    ).toBeInTheDocument();
    expect(within(root as HTMLElement).getByText("Child content")).toBeInTheDocument();
  });
});
