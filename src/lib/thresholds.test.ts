import { severityTier, tierColorVar } from "@/lib/thresholds";

describe("severityTier", () => {
  it("returns low below warn threshold", () => {
    expect(severityTier(10, 50, 75)).toBe("low");
  });

  it("returns warn between warn and alert thresholds", () => {
    expect(severityTier(50, 50, 75)).toBe("warn");
    expect(severityTier(74, 50, 75)).toBe("warn");
  });

  it("returns high at or above alert threshold", () => {
    expect(severityTier(75, 50, 75)).toBe("high");
    expect(severityTier(100, 50, 75)).toBe("high");
  });
});

describe("tierColorVar", () => {
  it("maps tiers to CSS variables", () => {
    expect(tierColorVar("low")).toBe("var(--severity-low)");
    expect(tierColorVar("warn")).toBe("var(--severity-warn)");
    expect(tierColorVar("high")).toBe("var(--severity-high)");
  });
});
