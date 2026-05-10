import { ONBOARDING_LANGUAGES } from "@/lib/onboardingLanguages";

describe("ONBOARDING_LANGUAGES", () => {
  it("lists hy-AM first with required fields", () => {
    expect(ONBOARDING_LANGUAGES[0]?.code).toBe("hy-AM");
    expect(ONBOARDING_LANGUAGES[0]).toMatchObject({
      native: expect.any(String),
      english: expect.any(String),
      flag: expect.any(String),
    });
  });

  it("contains Armenian row with expected labels", () => {
    const hy = ONBOARDING_LANGUAGES.find((r) => r.code === "hy-AM");
    expect(hy?.english).toBe("Armenian");
    expect(hy?.native).toContain("Հ");
  });

  it("has unique locale codes", () => {
    const codes = ONBOARDING_LANGUAGES.map((r) => r.code);
    expect(new Set(codes).size).toBe(codes.length);
  });
});
