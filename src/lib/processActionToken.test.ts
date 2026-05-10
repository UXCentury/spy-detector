import {
  killConfirmPayload,
  quarantineConfirmPayload,
  sha256HexUtf8,
} from "@/lib/processActionToken";

describe("sha256HexUtf8", () => {
  it("matches known SHA-256 for UTF-8 input", async () => {
    expect(await sha256HexUtf8("hello")).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });

  it("is stable for the same string across calls", async () => {
    const a = await sha256HexUtf8("KILL:1234:C:\\\\foo.exe");
    const b = await sha256HexUtf8("KILL:1234:C:\\\\foo.exe");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("confirm payloads", () => {
  it("builds kill payload with empty exe when null", () => {
    expect(killConfirmPayload(7, null)).toBe("KILL:7:");
  });

  it("builds quarantine payload with path", () => {
    expect(quarantineConfirmPayload(2, "C:\\\\x.exe")).toBe(
      "QUARANTINE:2:C:\\\\x.exe",
    );
  });
});
