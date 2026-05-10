import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";

export function useScanInterval(): {
  seconds: number | null;
  setSeconds: (v: number) => Promise<void>;
  loading: boolean;
  error: string | null;
} {
  const [seconds, setSecondsState] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await invoke<number>("get_scan_interval");
      setSecondsState(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => void reload());
  }, [reload]);

  const setSeconds = useCallback(
    async (v: number) => {
      setError(null);
      await invoke("set_scan_interval", { seconds: v });
      await reload();
    },
    [reload],
  );

  return { seconds, setSeconds, loading, error };
}
