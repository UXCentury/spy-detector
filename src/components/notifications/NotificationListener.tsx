"use client";

/**
 * Dedupe strategy (avoids double notifications when the same incident is both
 * emitted as a dedicated Tauri event and mirrored into the audit log):
 *
 * - Use `alert` for score-based and remote-thread findings; never show
 *   `event_logged` rows for `alert-emitted`, `finding-new`, `scan-completed`,
 *   `thread-injection`, `thread-burst`, or `camera-access`.
 * - Use `thread_event` for remote-thread and thread-burst UI; the log mirror
 *   for those kinds is ignored.
 * - Use `monitoring_tick` for camera PID transitions (matches SoundProvider
 *   dedupe); ignore `event_logged` `camera-access`.
 * - Use `event_logged` only for kinds without a dedicated listener above:
 *   `microphone-access`, `process-killed`, `process-quarantined`,
 *   `autostart-added`.
 * - A 5s TTL key map collapses rare races where `alert` and `thread_event`
 *   still describe the same remote-thread target PID (`rt:<pid>`).
 */

import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useRef } from "react";

import { useNotificationCenter } from "@/components/notifications/NotificationCenter";
import type { MonitoringTick, ScanCompletedEvent } from "@/lib/types/monitoring";
import type { Finding, ProcessRow } from "@/lib/types";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";

const DEDUPE_TTL_MS = 5000;
const dedupeExpiry = new Map<string, number>();

function shouldSkipDedupe(key: string): boolean {
  const now = Date.now();
  for (const [k, exp] of dedupeExpiry) {
    if (exp <= now) dedupeExpiry.delete(k);
  }
  const exp = dedupeExpiry.get(key);
  if (exp != null && exp > now) return true;
  dedupeExpiry.set(key, now + DEDUPE_TTL_MS);
  return false;
}

const CAMERA_MIC_WINDOW_MS = 30_000;
const cameraLast = new Map<number, number>();
const micLast = new Map<string, number>();

function allowCamera(pid: number): boolean {
  const now = Date.now();
  const last = cameraLast.get(pid) ?? 0;
  if (now - last < CAMERA_MIC_WINDOW_MS) return false;
  cameraLast.set(pid, now);
  return true;
}

function allowMic(key: string): boolean {
  const now = Date.now();
  const last = micLast.get(key) ?? 0;
  if (now - last < CAMERA_MIC_WINDOW_MS) return false;
  micLast.set(key, now);
  return true;
}

type ThreadEventPayload = {
  kind: string;
  suspicious: boolean;
  sourcePid: number;
  sourceName: string;
  targetPid: number;
  targetName: string;
  severity?: string;
};

type AlertPayload = Finding & { severity?: string };

type EventLoggedPayload = {
  id: number;
  kind?: string;
  severity?: string;
  summary?: string;
  processName?: string | null;
  pid?: number | null;
};

function mapAlertSeverity(
  p: AlertPayload,
): "warn" | "high" | null {
  const s = p.severity?.toLowerCase();
  if (s === "info" || s === "low") return null;
  if (s === "warn") return "warn";
  if (s === "high") return "high";
  if (p.score >= 75) return "high";
  return "warn";
}

function alertDedupeKey(p: AlertPayload): string {
  if (p.reasons?.some((r) => /remote thread/i.test(r))) {
    return `rt:${p.pid}`;
  }
  return `alert:${p.pid}`;
}

async function resolveProcessName(pid: number): Promise<string> {
  try {
    const rows = await invoke<ProcessRow[]>("list_processes");
    const r = rows.find((x) => x.pid === pid);
    return r?.name ?? `PID ${pid}`;
  } catch {
    return `PID ${pid}`;
  }
}

export function NotificationListener() {
  const { t } = useLang();
  const { push, prefs } = useNotificationCenter();
  const prefsRef = useRef(prefs);
  const pushRef = useRef(push);
  const tRef = useRef(t);

  const prevCameraPidsRef = useRef<Set<number>>(new Set());
  const cameraTickPrimedRef = useRef(false);

  useEffect(() => {
    prefsRef.current = prefs;
  }, [prefs]);

  useEffect(() => {
    pushRef.current = push;
  }, [push]);

  useEffect(() => {
    tRef.current = t;
  }, [t]);

  useEffect(() => {
    // Subscriptions are stable; handlers read prefsRef / pushRef / tRef each emit.
    if (typeof window === "undefined" || !isTauri()) return;

    let cancelled = false;
    const pending: UnlistenFn[] = [];

    const tp = (key: StringKey) => tRef.current(key);

    const onAlert = (e: Event<AlertPayload>) => {
      const p = e.payload;
      const sev = mapAlertSeverity(p);
      if (sev == null) return;
      const dk = alertDedupeKey(p);
      if (shouldSkipDedupe(dk)) return;
      const title =
        p.reasons?.[0] != null && p.reasons[0].trim() !== ""
          ? p.reasons[0]
          : tp("notifications.alerts.alert");
      const body = `${p.name} · ${tp("notifications.alerts.scanScore").replace("{score}", String(p.score))}`;
      pushRef.current({
        severity: sev,
        icon: "alert",
        title,
        body,
        href: "/alerts",
      });
    };

    const onThread = (e: Event<ThreadEventPayload>) => {
      const p = e.payload;
      if (p.kind === "remote_thread" && p.suspicious) {
        if (p.severity !== "high") return;
        if (shouldSkipDedupe(`rt:${p.targetPid}`)) return;
        pushRef.current({
          severity: "high",
          icon: "thread",
          title: tp("notifications.alerts.remoteThread"),
          body: `${p.sourceName} → ${p.targetName}`,
          href: "/activity",
        });
        return;
      }
      if (p.kind === "thread_burst") {
        if (shouldSkipDedupe(`tb:${p.sourcePid}`)) return;
        pushRef.current({
          severity: "warn",
          icon: "thread",
          title: tp("notifications.alerts.threadBurst"),
          body: tp("notifications.alerts.threadBurstDetail").replace(
            "{name}",
            p.sourceName,
          ),
          href: "/activity",
        });
      }
    };

    const onScan = (e: Event<ScanCompletedEvent>) => {
      if (e.payload.maxScore < 70) return;
      if (shouldSkipDedupe(`scan:${e.payload.at}`)) return;
      pushRef.current({
        severity: "high",
        icon: "scan",
        title: tp("notifications.alerts.scanHigh"),
        body: tp("notifications.alerts.scanScore").replace(
          "{score}",
          String(e.payload.maxScore),
        ),
        href: "/",
      });
    };

    const onMonitoringTick = (e: Event<MonitoringTick>) => {
      if (!prefsRef.current.cameraMic) return;
      const pids = e.payload.activeCameraPids ?? [];
      const next = new Set(pids);
      if (cameraTickPrimedRef.current) {
        for (const pid of next) {
          if (!prevCameraPidsRef.current.has(pid)) {
            if (!allowCamera(pid)) continue;
            void (async () => {
              const name = await resolveProcessName(pid);
              pushRef.current({
                severity: "warn",
                icon: "camera",
                title: tp("notifications.alerts.cameraInUse"),
                body: `${name} (${pid})`,
                href: "/activity",
              });
            })();
          }
        }
      } else {
        cameraTickPrimedRef.current = true;
      }
      prevCameraPidsRef.current = next;
    };

    const onEventLogged = (e: Event<EventLoggedPayload>) => {
      const k = e.payload.kind;
      if (!k) return;

      if (k === "microphone-access") {
        if (!prefsRef.current.cameraMic) return;
        const micKey = `${e.payload.pid ?? "x"}:${e.payload.summary ?? ""}`;
        if (!allowMic(micKey)) return;
        const proc =
          e.payload.processName != null && e.payload.processName !== ""
            ? e.payload.processName
            : e.payload.summary ?? "";
        pushRef.current({
          severity: "warn",
          icon: "mic",
          title: tp("notifications.alerts.micInUse"),
          body: proc,
          href: "/activity",
        });
        return;
      }

      if (k === "process-killed") {
        if (!prefsRef.current.actions) return;
        const name =
          e.payload.processName != null && e.payload.processName !== ""
            ? e.payload.processName
            : e.payload.summary ?? "";
        pushRef.current({
          severity: "high",
          icon: "kill",
          title: tp("notifications.alerts.killed"),
          body: name,
          href: "/logs",
        });
        return;
      }

      if (k === "process-quarantined") {
        if (!prefsRef.current.actions) return;
        const name =
          e.payload.processName != null && e.payload.processName !== ""
            ? e.payload.processName
            : e.payload.summary ?? "";
        pushRef.current({
          severity: "high",
          icon: "kill",
          title: tp("notifications.alerts.quarantined"),
          body: name,
          href: "/logs",
        });
        return;
      }

      if (k === "autostart-added") {
        if (!prefsRef.current.autostart) return;
        pushRef.current({
          severity: "low",
          icon: "shield",
          title: tp("notifications.alerts.autostart"),
          body: e.payload.summary ?? "",
          href: "/logs",
        });
      }
    };

    void (async () => {
      try {
        const u1 = await listen<AlertPayload>("alert", onAlert);
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

        const u5 = await listen<EventLoggedPayload>(
          "event_logged",
          onEventLogged,
        );
        if (cancelled) {
          u5();
          pending.forEach((u) => u());
          return;
        }
        pending.push(u5);
      } catch {
        /* ignore */
      }
    })();

    return () => {
      cancelled = true;
      pending.forEach((u) => u());
    };
  }, []);

  return null;
}
