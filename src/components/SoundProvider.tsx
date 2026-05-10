"use client";

import { isTauri } from "@tauri-apps/api/core";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  playCameraOpened,
  playIssueDetected,
  setSoundEnabled as setModuleSoundEnabled,
  setSoundOnCamera as setModuleSoundOnCamera,
  setSoundOnIssue as setModuleSoundOnIssue,
} from "@/lib/sound/issueSound";
import type { MonitoringTick, ScanCompletedEvent } from "@/lib/types/monitoring";
import type { Finding } from "@/lib/types";

type AlertSoundPayload = Finding & { severity?: string };

type ThreadEventPayload = {
  kind: string;
  suspicious: boolean;
};

type SoundContextValue = {
  enabled: boolean;
  setEnabled: (v: boolean) => void;
  volume: number;
  setVolume: (v: number) => void;
  soundOnIssue: boolean;
  setSoundOnIssue: (v: boolean) => void;
  soundOnCamera: boolean;
  setSoundOnCamera: (v: boolean) => void;
};

const SoundContext = createContext<SoundContextValue | null>(null);

function readStoredEnabled(): boolean {
  if (typeof window === "undefined") return true;
  return localStorage.getItem("soundEnabled") !== "false";
}

function readStoredVolume(): number {
  if (typeof window === "undefined") return 0.5;
  const raw = localStorage.getItem("soundVolume");
  const v = raw == null ? NaN : Number.parseFloat(raw);
  if (!Number.isFinite(v)) return 0.5;
  return Math.max(0, Math.min(1, v));
}

function readStoredSub(key: string): boolean {
  if (typeof window === "undefined") return true;
  const raw = localStorage.getItem(key);
  if (raw === null) return true;
  return raw !== "false";
}

export function SoundProvider({ children }: { children: ReactNode }) {
  const [enabled, setEnabledState] = useState(readStoredEnabled);
  const [volume, setVolumeState] = useState(readStoredVolume);
  const [soundOnIssue, setSoundOnIssueState] = useState(() =>
    readStoredSub("soundOnIssue"),
  );
  const [soundOnCamera, setSoundOnCameraState] = useState(() =>
    readStoredSub("soundOnCamera"),
  );

  const enabledRef = useRef(enabled);
  const volumeRef = useRef(volume);
  useLayoutEffect(() => {
    enabledRef.current = enabled;
    volumeRef.current = volume;
  }, [enabled, volume]);

  const prevCameraPidsRef = useRef<Set<number>>(new Set());
  const cameraTickPrimedRef = useRef(false);

  const setEnabled = useCallback((v: boolean) => {
    setEnabledState(v);
    setModuleSoundEnabled(v);
  }, []);

  const setVolume = useCallback((v: number) => {
    const clamped = Math.max(0, Math.min(1, v));
    setVolumeState(clamped);
    if (typeof window !== "undefined") {
      localStorage.setItem("soundVolume", String(clamped));
    }
  }, []);

  const setSoundOnIssue = useCallback((v: boolean) => {
    setSoundOnIssueState(v);
    setModuleSoundOnIssue(v);
  }, []);

  const setSoundOnCamera = useCallback((v: boolean) => {
    setSoundOnCameraState(v);
    setModuleSoundOnCamera(v);
  }, []);

  useEffect(() => {
    setModuleSoundEnabled(enabled);
  }, [enabled]);

  useEffect(() => {
    setModuleSoundOnIssue(soundOnIssue);
  }, [soundOnIssue]);

  useEffect(() => {
    setModuleSoundOnCamera(soundOnCamera);
  }, [soundOnCamera]);

  useEffect(() => {
    if (typeof window === "undefined" || !isTauri()) return;

    let cancelled = false;
    const pending: UnlistenFn[] = [];

    const onAlert = (e: Event<AlertSoundPayload>) => {
      if (!enabledRef.current) return;
      if (e.payload.severity === "low") return;
      playIssueDetected({ volume: volumeRef.current });
    };

    const onThread = (e: Event<ThreadEventPayload>) => {
      if (!enabledRef.current) return;
      const p = e.payload;
      if (p.kind === "remote_thread" && p.suspicious) {
        playIssueDetected({ volume: volumeRef.current });
      }
    };

    const onScan = (e: Event<ScanCompletedEvent>) => {
      if (!enabledRef.current) return;
      if (e.payload.maxScore >= 70) {
        playIssueDetected({ volume: volumeRef.current });
      }
    };

    const onMonitoringTick = (e: Event<MonitoringTick>) => {
      if (!enabledRef.current) return;
      const pids = e.payload.activeCameraPids ?? [];
      const next = new Set(pids);
      if (cameraTickPrimedRef.current) {
        for (const pid of next) {
          if (!prevCameraPidsRef.current.has(pid)) {
            playCameraOpened({ volume: volumeRef.current });
          }
        }
      } else {
        cameraTickPrimedRef.current = true;
      }
      prevCameraPidsRef.current = next;
    };

    void (async () => {
      try {
        const u1 = await listen<AlertSoundPayload>("alert", onAlert);
        if (cancelled) {
          u1();
          return;
        }
        pending.push(u1);

        const u2 = await listen<ThreadEventPayload>("thread_event", onThread);
        if (cancelled) {
          u2();
          pending.forEach((u) => u());
          return;
        }
        pending.push(u2);

        const u3 = await listen<ScanCompletedEvent>("scan_completed", onScan);
        if (cancelled) {
          u3();
          pending.forEach((u) => u());
          return;
        }
        pending.push(u3);

        const u4 = await listen<MonitoringTick>(
          "monitoring_tick",
          onMonitoringTick,
        );
        if (cancelled) {
          u4();
          pending.forEach((u) => u());
          return;
        }
        pending.push(u4);
      } catch {
        /* ignore */
      }
    })();

    return () => {
      cancelled = true;
      pending.forEach((u) => u());
    };
  }, []);

  const value = useMemo(
    () => ({
      enabled,
      setEnabled,
      volume,
      setVolume,
      soundOnIssue,
      setSoundOnIssue,
      soundOnCamera,
      setSoundOnCamera,
    }),
    [
      enabled,
      setEnabled,
      volume,
      setVolume,
      soundOnIssue,
      setSoundOnIssue,
      soundOnCamera,
      setSoundOnCamera,
    ],
  );

  return (
    <SoundContext.Provider value={value}>{children}</SoundContext.Provider>
  );
}

export function useSound(): SoundContextValue {
  const ctx = useContext(SoundContext);
  if (!ctx) {
    throw new Error("useSound must be used within SoundProvider");
  }
  return ctx;
}
