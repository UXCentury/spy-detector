import { renderHook, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";

import { useScanInterval } from "@/lib/hooks/useScanInterval";

describe("useScanInterval", () => {
  it("returns seconds from get_scan_interval when IPC succeeds", async () => {
    vi.mocked(invoke).mockResolvedValue(240);

    const { result } = renderHook(() => useScanInterval());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.seconds).toBe(240);
    expect(result.current.error).toBeNull();
  });

  it("surfaces invoke errors and leaves seconds null (no implicit default)", async () => {
    vi.mocked(invoke).mockRejectedValue(new Error("get_scan_interval failed"));

    const { result } = renderHook(() => useScanInterval());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.seconds).toBeNull();
    expect(result.current.error).toBe("get_scan_interval failed");
  });
});
