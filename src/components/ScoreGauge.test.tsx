import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScoreGauge } from "@/components/ScoreGauge";

describe("ScoreGauge", () => {
  it("uses low severity colour when score is below warn threshold", () => {
    const { container } = render(
      <ScoreGauge
        score={20}
        warnThreshold={50}
        alertThreshold={75}
        animate={false}
      />,
    );

    const strokes = container.querySelectorAll("circle[stroke]");
    expect(strokes.length).toBeGreaterThanOrEqual(2);
    const progressStroke = strokes[1]?.getAttribute("stroke");
    expect(progressStroke).toBe("var(--severity-low)");
  });

  it("uses high severity colour when score meets alert threshold", () => {
    const { container } = render(
      <ScoreGauge
        score={90}
        warnThreshold={50}
        alertThreshold={75}
        animate={false}
      />,
    );

    const strokes = container.querySelectorAll("circle[stroke]");
    const progressStroke = strokes[1]?.getAttribute("stroke");
    expect(progressStroke).toBe("var(--severity-high)");
  });
});
