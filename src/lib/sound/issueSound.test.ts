import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("issueSound", () => {
  const playMock = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
    vi.stubGlobal(
      "Audio",
      class MockAudio {
        preload = "auto";
        volume = 0.5;
        currentTime = 0;
        play = playMock;
        constructor() {}
      },
    );
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-09T10:00:00.000Z"));
    playMock.mockClear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("setSoundEnabled gates playback via isSoundEnabled", async () => {
    const sound = await import("@/lib/sound/issueSound");
    sound.setSoundEnabled(false);
    sound.playIssueDetected({ force: true });
    expect(playMock).not.toHaveBeenCalled();
    sound.setSoundEnabled(true);
    sound.playIssueDetected({ force: true });
    expect(playMock).toHaveBeenCalledTimes(1);
  });

  it("rate-limits playIssueDetected within MIN_INTERVAL_MS unless force", async () => {
    const sound = await import("@/lib/sound/issueSound");
    sound.setSoundEnabled(true);
    sound.setSoundOnIssue(true);
    sound.playIssueDetected();
    sound.playIssueDetected();
    expect(playMock).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(3999);
    sound.playIssueDetected();
    expect(playMock).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(2);
    sound.playIssueDetected();
    expect(playMock).toHaveBeenCalledTimes(2);
  });

  it("honours force bypassing issue flag and rate limit window", async () => {
    const sound = await import("@/lib/sound/issueSound");
    sound.setSoundEnabled(true);
    sound.setSoundOnIssue(false);
    sound.playIssueDetected({ force: true });
    sound.playIssueDetected({ force: true });
    expect(playMock).toHaveBeenCalledTimes(2);
  });
});
