import { strings } from "@/lib/i18n/catalog";
import { translate } from "@/lib/i18n/helpers";
import type { StringKey } from "@/lib/i18n/types";

describe("translate", () => {
  it("substitutes {count} when callers use replace (catalog pattern)", () => {
    const template = translate("overview.heroHighSeverityMany", "en-US");
    expect(template.replace("{count}", String(3))).toBe(
      "3 high-severity findings",
    );
  });

  it("falls back to English when the locale has no entry for that key", () => {
    const viaGb = translate("overview.heroHighSeverityMany", "en-GB");
    const en = translate("overview.heroHighSeverityMany", "en-US");
    expect(viaGb).toBe(en);
    expect(en).toBe("{count} high-severity findings");
  });

  it("returns Armenian copy when present in catalog", () => {
    const titleHy = translate("overview.title", "hy-AM");
    expect(titleHy).not.toBe(translate("overview.title", "en-US"));
    expect(titleHy.length).toBeGreaterThan(0);
  });
});

describe("invalid keys at runtime", () => {
  it("translate throws or returns empty when row missing (current behavior)", () => {
    const key = "definitely.missing.key.zzz" as StringKey;
    expect(strings[key]).toBeUndefined();
    expect(() => translate(key, "en-US")).toThrow(TypeError);
  });
});
