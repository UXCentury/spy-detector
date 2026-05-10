"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, Bug, Crosshair, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { PulseDot } from "@/components/PulseDot";
import { useToast } from "@/components/Toast";
import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import { useTauriEvent } from "@/lib/hooks/useTauriEvent";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";

type ProcessLaunchRow = {
  id: number;
  ts: string;
  pid: number;
  name: string;
  path: string;
  ppid: number;
  parentName: string;
  classification: string;
  signed: boolean;
};

type ProcessLaunchedPayload = Omit<ProcessLaunchRow, "id">;

type ThreadEventPayload = {
  ts: string;
  kind: string;
  sourcePid: number;
  sourceName: string;
  sourcePath: string;
  targetPid: number;
  targetName: string;
  targetPath: string;
  suspicious: boolean;
};

type ThreadEventRow = ThreadEventPayload & { id: number };

const DEFAULT_CLASSIFICATIONS = new Set([
  "unsigned",
  "user-writable-path",
  "signed-third-party",
]);

const CLASSIFICATION_KEYS: string[] = [
  "system",
  "signed-third-party",
  "unsigned",
  "user-writable-path",
];

function formatTimeAgo(iso: string): string {
  const diff = Date.now() - Date.parse(iso);
  if (Number.isNaN(diff) || diff < 0) return "—";
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h`;
}

function countLaunches5m(rows: { ts: string }[]): number {
  const cutoff = Date.now() - 5 * 60 * 1000;
  return rows.filter((r) => Date.parse(r.ts) >= cutoff).length;
}

function truncatePath(p: string, max = 72): string {
  if (p.length <= max) return p;
  return `${p.slice(0, max - 1)}…`;
}

function classificationLabel(classification: string, t: (k: StringKey) => string): string {
  switch (classification) {
    case "system":
      return t("activity.classification.system");
    case "signed-third-party":
      return t("activity.classification.signed");
    case "unsigned":
      return t("activity.classification.unsigned");
    case "user-writable-path":
      return t("activity.classification.userPath");
    default:
      return classification;
  }
}

function badgeClass(classification: string): string {
  switch (classification) {
    case "system":
      return "border-(--border) bg-(--surface-2) text-(--muted)";
    case "signed-third-party":
      return "border-emerald-500/35 bg-emerald-500/10 text-emerald-200";
    case "unsigned":
      return "border-amber-500/40 bg-amber-500/10 text-amber-100";
    case "user-writable-path":
      return "border-(--severity-high)/45 bg-(--severity-high)/15 text-(--foreground)";
    default:
      return "border-(--border) bg-(--surface-2) text-(--muted)";
  }
}

export default function ActivityPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const { tick } = useMonitoringTick();
  const [launches, setLaunches] = useState<ProcessLaunchRow[]>([]);
  const [threads, setThreads] = useState<ThreadEventRow[]>([]);
  const [filterAll, setFilterAll] = useState(false);
  const [filterSet, setFilterSet] = useState<Set<string>>(
    () => new Set(DEFAULT_CLASSIFICATIONS),
  );
  const [seedDone, setSeedDone] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const launchesLive = tick?.etwProcessActive ?? false;
  const threadsLive =
    (tick?.elevated ?? false) && (tick?.etwProcessActive ?? false);

  const filteredLaunches = useMemo(() => {
    if (filterAll) return launches;
    return launches.filter((r) => filterSet.has(r.classification));
  }, [launches, filterAll, filterSet]);

  const launches5m = useMemo(() => countLaunches5m(launches), [launches]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const results = await Promise.allSettled([
          invoke<ProcessLaunchRow[]>("get_recent_process_launches", { limit: 200 }),
          invoke<ThreadEventRow[]>("get_recent_thread_events", { limit: 100 }),
        ]);
        if (cancelled) return;
        const [lr, tr] = results;
        if (lr.status === "fulfilled") setLaunches(lr.value);
        if (tr.status === "fulfilled") setThreads(tr.value);
        if (lr.status === "rejected") {
          console.error("[activity] ipc failed", lr.reason);
        }
        if (tr.status === "rejected") {
          console.error("[activity] ipc failed", tr.reason);
        }
        if (lr.status === "rejected" || tr.status === "rejected") {
          showToast(t("common.error"), "error");
        }
      } finally {
        if (!cancelled) {
          setSeedDone(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [showToast, t]);

  usePageReady(seedDone);

  useTauriEvent<ProcessLaunchedPayload>("process_launched", (e) => {
    const row: ProcessLaunchRow = {
      id: Date.now(),
      ...e.payload,
    };
    setLaunches((prev) => [row, ...prev].slice(0, 200));
  });

  useTauriEvent<ThreadEventPayload>("thread_event", (e) => {
    const row: ThreadEventRow = {
      id: Date.now(),
      ...e.payload,
    };
    setThreads((prev) => [row, ...prev].slice(0, 100));
  });

  const toggleClassification = (key: string) => {
    setFilterAll(false);
    setFilterSet((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
        if (next.size === 0) return new Set(DEFAULT_CLASSIFICATIONS);
        return next;
      }
      next.add(key);
      return next;
    });
  };

  const clearLaunches = async () => {
    try {
      await invoke("clear_process_launches");
      if (!mountedRef.current) return;
      setLaunches([]);
      showToast(t("common.success"), "success");
    } catch (e) {
      console.error("[activity] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(t("common.error"), "error");
    }
  };

  const clearThreads = async () => {
    try {
      await invoke("clear_thread_events");
      if (!mountedRef.current) return;
      setThreads([]);
      showToast(t("common.success"), "success");
    } catch (e) {
      console.error("[activity] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(t("common.error"), "error");
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("activity.title")}</h1>
        <p className="mt-2 max-w-2xl text-sm text-(--muted)">{t("activity.subtitle")}</p>
      </div>

      <section className="rounded-xl border border-(--border) bg-(--surface)/60 shadow-sm backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-(--border) px-4 py-3">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {launchesLive ? (
              <PulseDot color="var(--severity-low)" />
            ) : (
              <span
                className="inline-block size-2 shrink-0 rounded-full bg-(--muted)"
                aria-hidden
              />
            )}
            <h2 className="text-sm font-semibold text-(--foreground)">
              {t("activity.launches.title")}
            </h2>
            <span className="text-xs text-(--muted)">
              {t("activity.launches.last5m").replace("{count}", String(launches5m))}
            </span>
          </div>
          <button
            type="button"
            onClick={() => void clearLaunches()}
            className="rounded-lg border border-(--border) bg-(--surface-2) px-2.5 py-1.5 text-xs font-medium text-(--foreground) transition-colors hover:border-(--accent)/40"
          >
            {t("activity.clear")}
          </button>
        </div>

        <div className="flex flex-wrap gap-1.5 px-4 py-2">
          <button
            type="button"
            onClick={() => setFilterAll(true)}
            className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
              filterAll
                ? "border-(--accent) bg-(--accent)/15 text-(--foreground)"
                : "border-(--border) bg-(--surface-2) text-(--muted) hover:text-(--foreground)"
            }`}
          >
            {t("activity.filters.all")}
          </button>
          {CLASSIFICATION_KEYS.map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => toggleClassification(key)}
              className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                !filterAll && filterSet.has(key)
                  ? "border-(--accent)/50 bg-(--accent)/10 text-(--foreground)"
                  : "border-(--border) bg-(--surface-2) text-(--muted) hover:text-(--foreground)"
              }`}
            >
              {classificationLabel(key, t)}
            </button>
          ))}
        </div>

        <div className="max-h-[min(520px,55vh)] overflow-y-auto px-2 pb-3">
          {filteredLaunches.length === 0 ? (
            <div className="px-3 py-12 text-center text-sm text-(--muted)">
              {t("activity.launches.empty")}
            </div>
          ) : (
            <ul className="space-y-2 px-2 pt-1">
              <AnimatePresence initial={false}>
                {filteredLaunches.map((r) => (
                  <motion.li
                    key={`${r.id}-${r.ts}-${r.pid}`}
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.18 }}
                    className="rounded-lg border border-(--border)/80 bg-(--background)/40 px-3 py-2"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-[10px] text-(--muted)">
                            {formatTimeAgo(r.ts)}
                          </span>
                          <span className="font-medium text-(--foreground)">{r.name}</span>
                          <span className="font-mono text-[11px] text-(--muted)">
                            pid {r.pid}
                          </span>
                          <span
                            className={`rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${badgeClass(r.classification)}`}
                          >
                            {classificationLabel(r.classification, t)}
                          </span>
                        </div>
                        <div className="mt-1 font-mono text-[11px] text-(--muted)">
                          {truncatePath(r.path)}
                        </div>
                        <div className="mt-0.5 text-[11px] text-(--muted)">
                          parent: {r.parentName || "—"}{" "}
                          <span className="font-mono">({r.ppid})</span>
                        </div>
                      </div>
                    </div>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          )}
        </div>
      </section>

      <section className="rounded-xl border border-(--border) bg-(--surface)/60 shadow-sm backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-(--border) px-4 py-3">
          <div className="flex items-center gap-2">
            {threadsLive ? (
              <PulseDot color="var(--severity-low)" />
            ) : (
              <span
                className="inline-block size-2 shrink-0 rounded-full bg-(--muted)"
                aria-hidden
              />
            )}
            <h2 className="text-sm font-semibold text-(--foreground)">
              {t("activity.threads.title")}
            </h2>
          </div>
          <button
            type="button"
            onClick={() => void clearThreads()}
            className="rounded-lg border border-(--border) bg-(--surface-2) px-2.5 py-1.5 text-xs font-medium text-(--foreground) transition-colors hover:border-(--accent)/40"
          >
            {t("activity.clear")}
          </button>
        </div>

        <div className="px-4 py-4">
          {threads.length === 0 ? (
            <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-(--border) bg-(--surface)/40 px-6 py-12 text-center">
              <ShieldCheck className="size-8 text-(--muted)" aria-hidden />
              <p className="max-w-md text-sm text-(--muted)">{t("activity.threads.empty")}</p>
            </div>
          ) : (
            <ul className="space-y-2">
              <AnimatePresence initial={false}>
                {threads.map((ev) => {
                  const Icon = ev.kind === "thread_burst" ? Bug : Crosshair;
                  const tag =
                    ev.kind === "thread_burst"
                      ? t("activity.threads.threadBurst")
                      : t("activity.threads.remoteThread");
                  return (
                    <motion.li
                      key={`${ev.id}-${ev.ts}-${ev.kind}`}
                      initial={{ opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.18 }}
                      className="rounded-lg border border-(--border)/80 bg-(--background)/40 px-3 py-2"
                    >
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        <Icon className="size-4 shrink-0 text-(--accent)" aria-hidden />
                        <span className="font-mono text-[10px] text-(--muted)">
                          {formatTimeAgo(ev.ts)}
                        </span>
                        <span className="rounded-md border border-(--border) bg-(--surface-2) px-1.5 py-0.5 text-[10px] font-medium text-(--foreground)">
                          {tag}
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs text-(--foreground)">
                        <span className="font-medium">{ev.sourceName}</span>
                        <span className="font-mono text-(--muted)">({ev.sourcePid})</span>
                        <ArrowRight className="size-3.5 text-(--muted)" aria-hidden />
                        <span className="font-medium">{ev.targetName}</span>
                        <span className="font-mono text-(--muted)">({ev.targetPid})</span>
                      </div>
                      <div className="mt-1 font-mono text-[10px] text-(--muted)">
                        {truncatePath(ev.sourcePath)} → {truncatePath(ev.targetPath)}
                      </div>
                    </motion.li>
                  );
                })}
              </AnimatePresence>
            </ul>
          )}
        </div>
      </section>
    </div>
  );
}
