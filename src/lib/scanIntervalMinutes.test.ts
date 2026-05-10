import {
  buildAllowedScanMinutes,
  formatMinutesDuration,
  nearestAllowedMinutes,
} from "@/lib/scanIntervalMinutes";

describe("buildAllowedScanMinutes", () => {
  it("includes early minute steps, hourly-ish blocks, and 1 day", () => {
    const allowed = buildAllowedScanMinutes();
    expect(allowed[0]).toBe(1);
    expect(allowed).toContain(30);
    expect(allowed).toContain(35);
    expect(allowed).toContain(1440);
    expect(allowed.length).toBe(92);
  });
});

describe("nearestAllowedMinutes", () => {
  const allowed = buildAllowedScanMinutes();

  it("round-trips every allowed value to itself", () => {
    for (const m of allowed) {
      expect(nearestAllowedMinutes(m, allowed)).toBe(m);
    }
  });

  it("snaps to closest bucket for off-grid values", () => {
    expect(nearestAllowedMinutes(33, allowed)).toBe(35);
    expect(nearestAllowedMinutes(32, allowed)).toBe(30);
  });

  it("round-trips minutes derived from seconds like settings do", () => {
    const minutes = 45;
    const secs = Math.round(minutes * 60);
    const back = nearestAllowedMinutes(
      Math.max(1, Math.round(secs / 60)),
      allowed,
    );
    expect(back).toBe(minutes);
  });
});

describe("formatMinutesDuration", () => {
  it("formats singular minute", () => {
    expect(formatMinutesDuration(1)).toBe("1 minute");
  });

  it("formats day boundary label", () => {
    expect(formatMinutesDuration(1440)).toBe("1 day");
  });

  it("formats hours with optional minutes", () => {
    expect(formatMinutesDuration(120)).toBe("2 hours");
    expect(formatMinutesDuration(125)).toBe("2 hours 5 minutes");
  });
});
