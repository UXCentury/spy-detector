"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { EyeOff, ShieldOff, Skull } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { IgnoreActionModal } from "./IgnoreActionModal";
import { ProcessActionModal } from "./ProcessActionModal";
import { ProcessDrawer } from "./ProcessDrawer";
import { ProgressBar } from "@/components/ProgressBar";
import { PulseDot } from "@/components/PulseDot";
import { ScoreGauge } from "@/components/ScoreGauge";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { useToast } from "@/components/Toast";
import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import { useScanCompleted } from "@/lib/hooks/useScanCompleted";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type { Finding, ProcessRow } from "@/lib/types";
import { severityTier } from "@/lib/thresholds";

function liveEtwCopy(
  tick: ReturnType<typeof useMonitoringTick>["tick"],
  t: (key: StringKey) => string,
): {
  color: string;
  label: string;
} {
  if (!tick) {
    return { color: "var(--muted)", label: t("processes.liveConnecting") };
  }
  if (tick.etwProcessActive && tick.etwWin32kActive) {
    return { color: "var(--severity-low)", label: t("processes.live.online") };
  }
  if (tick.etwProcessActive || tick.etwWin32kActive) {
    return { color: "var(--severity-warn)", label: t("processes.live.partial") };
  }
  return { color: "var(--severity-high)", label: t("processes.live.offline") };
}

type ThresholdSettings = {
  warnThreshold: number;
  alertThreshold: number;
};

type FilterTier = "all" | "high" | "warn" | "clean";

export default function ProcessesPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const { tick } = useMonitoringTick();
  const live = liveEtwCopy(tick, t);
  const [rows, setRows] = useState<ProcessRow[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [thresholds, setThresholds] = useState<ThresholdSettings>({
    warnThreshold: 50,
    alertThreshold: 75,
  });
  const [listLoading, setListLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [filter, setFilter] = useState<FilterTier>("all");
  const [search, setSearch] = useState("");
  const [showIgnored, setShowIgnored] = useState(false);
  const [ignoreModal, setIgnoreModal] = useState<
    null | { imagePath: string; name: string }
  >(null);
  const [processActionModal, setProcessActionModal] = useState<
    null | { pid: number; name: string; variant: "kill" | "quarantine" }
  >(null);
  const navPrimedOnceRef = useRef(false);
  const [navPrimed, setNavPrimed] = useState(false);

  const loadProcesses = useCallback(async () => {
    setListLoading(true);
    try {
      const list = await invoke<ProcessRow[]>("list_processes");
      setRows(list);
    } catch (e) {
      console.error("[processes] ipc failed", e);
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setListLoading(false);
      if (!navPrimedOnceRef.current) {
        navPrimedOnceRef.current = true;
        setNavPrimed(true);
      }
    }
  }, [showToast]);

  const loadLatest = useCallback(async () => {
    try {
      const latest = await invoke<Finding[] | null>("get_latest_findings");
      if (latest?.length) setFindings(latest);
    } catch (e) {
      console.error("[processes] ipc failed", e);
      /* empty DB */
    }
  }, []);

  const refreshAfterDanger = useCallback(() => {
    void loadProcesses();
    void loadLatest();
  }, [loadProcesses, loadLatest]);

  const loadThresholds = useCallback(async () => {
    try {
      const s = await invoke<ThresholdSettings>("get_app_settings");
      setThresholds({
        warnThreshold: s.warnThreshold,
        alertThreshold: s.alertThreshold,
      });
    } catch (e) {
      console.error("[processes] ipc failed", e);
      /* defaults */
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => {
      void loadProcesses();
      void loadLatest();
      void loadThresholds();
    });
  }, [loadProcesses, loadLatest, loadThresholds]);

  usePageReady(navPrimed);

  useScanCompleted(() => {
    void loadLatest();
    void loadProcesses();
  });

  const runScan = async () => {
    setScanLoading(true);
    try {
      const next = await invoke<Finding[]>("run_scan");
      setFindings(next);
      setSelected(null);
      showToast(t("overview.scanFinishedToast"), "success");
    } catch (e) {
      console.error("[processes] ipc failed", e);
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setScanLoading(false);
    }
  };

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (!showIgnored && f.ignored) return false;
      const tier = severityTier(
        f.score,
        thresholds.warnThreshold,
        thresholds.alertThreshold,
      );
      if (filter === "high" && tier !== "high") return false;
      if (filter === "warn" && tier !== "warn") return false;
      if (filter === "clean" && tier !== "low") return false;
      if (q && !f.name.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [findings, filter, search, thresholds, showIgnored]);

  const unignorePath = useCallback(
    async (imagePath: string) => {
      try {
        await invoke("remove_allowlist_entry", { imagePath });
        showToast(t("allowlist.removedToast"), "info");
        void loadLatest();
        void loadProcesses();
      } catch (e) {
        console.error("[processes] ipc failed", e);
        showToast(e instanceof Error ? e.message : String(e), "error");
      }
    },
    [loadLatest, loadProcesses, showToast, t],
  );

  const filteredRows = useMemo(
    () => rows.filter((r) => showIgnored || !r.ignored),
    [rows, showIgnored],
  );

  const ignoredCount = useMemo(() => {
    const findingPaths = new Set(
      findings.filter((f) => f.ignored && f.exePath).map((f) => f.exePath as string),
    );
    let count = findingPaths.size;
    for (const r of rows) {
      if (r.ignored && r.exePath && !findingPaths.has(r.exePath)) {
        count += 1;
      }
    }
    return count;
  }, [findings, rows]);

  const filterBtn = (id: FilterTier, label: string) => (
    <button
      key={id}
      type="button"
      onClick={() => setFilter(id)}
      className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-200 ${
        filter === id
          ? "border-(--accent) bg-(--accent)/20 text-(--foreground)"
          : "border-(--border) text-(--muted) hover:border-(--border-bright) hover:bg-(--surface-2)"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="space-y-10">
      <div className="space-y-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-tight">
                {t("processes.title")}
              </h1>
              <div className="flex items-center gap-2 rounded-full border border-(--border) bg-(--surface)/70 px-3 py-1 text-xs text-(--muted)">
                <PulseDot color={live.color} />
                <span className="font-medium text-(--foreground)">{live.label}</span>
              </div>
            </div>
            <p className="max-w-2xl text-sm text-(--muted)">
              {(() => {
                const path = "%APPDATA%\\spy-detector\\db.sqlite";
                const [before = "", after = ""] = t("processes.subtitle").split(
                  "{path}",
                );
                return (
                  <>
                    {before}
                    <span className="font-mono text-xs">{path}</span>
                    {after}
                  </>
                );
              })()}
            </p>
          </div>
          <div className="flex min-w-[200px] flex-1 flex-col items-stretch gap-2 sm:max-w-xs sm:flex-none">
            <button
              type="button"
              onClick={() => void runScan()}
              className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
              disabled={scanLoading}
            >
              {scanLoading ? t("processes.scanning") : t("processes.scanNow")}
            </button>
            {scanLoading ? <ProgressBar /> : null}
          </div>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
          <div className="flex flex-wrap items-center gap-2">
            {filterBtn("all", t("processes.filterAll"))}
            {filterBtn("high", t("processes.filterHigh"))}
            {filterBtn("warn", t("processes.filterWarn"))}
            {filterBtn("clean", t("processes.filterClean"))}
            <button
              type="button"
              role="switch"
              aria-checked={showIgnored}
              aria-label={t("processes.filters.showIgnored")}
              onClick={() => setShowIgnored((v) => !v)}
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-200 ${
                showIgnored
                  ? "border-(--accent) bg-(--accent)/20 text-(--foreground)"
                  : "border-(--border) text-(--muted) hover:border-(--border-bright) hover:bg-(--surface-2)"
              }`}
            >
              <EyeOff className="h-3.5 w-3.5" aria-hidden />
              <span>{t("processes.filters.showIgnored")}</span>
              {ignoredCount > 0 ? (
                <span
                  className={`inline-flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-semibold tabular-nums ${
                    showIgnored
                      ? "bg-(--accent) text-white"
                      : "bg-(--surface-2) text-(--muted)"
                  }`}
                >
                  {ignoredCount}
                </span>
              ) : null}
            </button>
          </div>
          <input
            type="search"
            placeholder={t("processes.searchPlaceholder")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-(--border) bg-(--surface)/80 px-3 py-2 text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none sm:ml-auto sm:max-w-xs"
          />
        </div>

        <div className="min-w-0 overflow-hidden rounded-xl border border-(--border) bg-(--surface)/40">
          <StickyTable className="sticky-table-wrap-flush">
            <table className="sticky-table table-fixed w-full min-w-[640px] text-left">
              <colgroup>
                <col style={{ width: 120 }} />
                <col style={{ width: 80 }} />
                <col style={{ width: 200 }} />
                <col style={{ width: 96 }} />
                <col />
              </colgroup>
              <thead>
                <tr>
                  <th className="col-sticky-left">{t("processes.colActions")}</th>
                  <th className="col-sticky-left-2" style={{ left: 120 }}>
                    {t("processes.colScore")}
                  </th>
                  <th className="col-sticky-left-3" style={{ left: 200 }}>
                    {t("processes.colName")}
                  </th>
                  <th>{t("processes.colPid")}</th>
                  <th>{t("processes.colImagePath")}</th>
                </tr>
              </thead>
              <tbody>
              <AnimatePresence initial={false}>
                {scanLoading
                  ? Array.from({ length: 8 }).map((_, i) => (
                      <tr key={`sk-${i}`}>
                        <td colSpan={5} className="px-4 py-2">
                          <Skeleton className="h-9 w-full" />
                        </td>
                      </tr>
                    ))
                  : filteredFindings.map((f, idx) => (
                      <motion.tr
                        key={`${f.pid}-${f.name}`}
                        layout
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -6 }}
                        transition={{
                          duration: 0.2,
                          delay: Math.min(idx, 12) * 0.03,
                          ease: [0.22, 1, 0.36, 1],
                        }}
                        className={`group cursor-pointer ${f.ignored ? "opacity-60" : ""}`}
                        onClick={() => setSelected(f)}
                        onKeyDown={(ev) => {
                          if (ev.key === "Enter" || ev.key === " ") {
                            ev.preventDefault();
                            setSelected(f);
                          }
                        }}
                        tabIndex={0}
                        role="button"
                      >
                        <td
                          className="col-sticky-left"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="flex justify-start gap-1 opacity-60 transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100">
                            <button
                              type="button"
                              disabled={f.pid === 0}
                              title={t("processes.endProcess")}
                              aria-label={t("processes.endProcess")}
                              onClick={(e) => {
                                e.stopPropagation();
                                setProcessActionModal({
                                  pid: f.pid,
                                  name: f.name,
                                  variant: "kill",
                                });
                              }}
                              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-(--muted) transition-colors duration-200 hover:bg-(--severity-high)/15 hover:text-(--severity-high) disabled:pointer-events-none disabled:opacity-40"
                            >
                              <Skull className="h-4 w-4" aria-hidden />
                            </button>
                            <button
                              type="button"
                              disabled={f.pid === 0}
                              title={t("processes.quarantine")}
                              aria-label={t("processes.quarantine")}
                              onClick={(e) => {
                                e.stopPropagation();
                                setProcessActionModal({
                                  pid: f.pid,
                                  name: f.name,
                                  variant: "quarantine",
                                });
                              }}
                              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-(--muted) transition-colors duration-200 hover:bg-(--severity-high)/15 hover:text-(--severity-high) disabled:pointer-events-none disabled:opacity-40"
                            >
                              <ShieldOff className="h-4 w-4" aria-hidden />
                            </button>
                            {!f.ignored ? (
                              <button
                                type="button"
                                disabled={!f.exePath}
                                title={t("processes.actions.ignore")}
                                aria-label={t("processes.actions.ignore")}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (!f.exePath) return;
                                  setIgnoreModal({
                                    imagePath: f.exePath,
                                    name: f.name,
                                  });
                                }}
                                className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-(--muted) transition-colors duration-200 hover:bg-(--accent)/15 hover:text-(--accent) disabled:pointer-events-none disabled:opacity-40"
                              >
                                <EyeOff className="h-4 w-4" aria-hidden />
                              </button>
                            ) : null}
                          </div>
                        </td>
                        <td className="col-sticky-left-2 align-middle" style={{ left: 120 }}>
                          <ScoreGauge
                            score={f.score}
                            warnThreshold={thresholds.warnThreshold}
                            alertThreshold={thresholds.alertThreshold}
                            size="sm"
                          />
                        </td>
                        <td className="col-sticky-left-3 min-w-0" style={{ left: 200 }}>
                          <div className="flex min-w-0 flex-nowrap items-center gap-2">
                            <span className="min-w-0 truncate" title={f.name}>
                              {f.name}
                            </span>
                            {f.ignored ? (
                              <span className="shrink-0 rounded-full border border-(--border) bg-(--surface-2)/70 px-2 py-0.5 text-[10px] font-medium text-(--muted)">
                                {t("processes.badges.ignored")}
                              </span>
                            ) : null}
                            {f.ignored && f.exePath ? (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  void unignorePath(f.exePath!);
                                }}
                                className="shrink-0 text-xs font-medium text-(--accent) opacity-0 transition-opacity duration-200 hover:underline group-hover:opacity-100"
                              >
                                {t("processes.actions.unignore")}
                              </button>
                            ) : null}
                          </div>
                        </td>
                        <td className="font-mono tabular-nums">{f.pid}</td>
                        <TruncCell
                          value={f.exePath ?? ""}
                          className="font-mono text-xs text-(--muted)"
                        />
                      </motion.tr>
                    ))}
              </AnimatePresence>
            </tbody>
          </table>
          </StickyTable>
          {!scanLoading && filteredFindings.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-(--muted)">
              {findings.length === 0
                ? t("processes.noScoredYet")
                : t("processes.noFilterMatches")}
            </div>
          ) : null}
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold tracking-tight">
              {t("processes.allProcessesTitle")}
            </h2>
            <p className="mt-1 max-w-2xl text-sm text-(--muted)">
              {t("processes.rawListSubtitle")}
            </p>
          </div>
          <button
            type="button"
            onClick={() => void loadProcesses()}
            className="rounded-lg border border-(--border) bg-(--surface)/80 px-4 py-2 text-sm font-medium transition-colors duration-200 hover:bg-(--surface-2) disabled:opacity-50"
            disabled={listLoading}
          >
            {listLoading ? t("processes.refreshingList") : t("processes.refreshList")}
          </button>
        </div>

        <div className="min-w-0 overflow-hidden rounded-xl border border-(--border) bg-(--surface)/40">
          <StickyTable className="sticky-table-wrap-flush">
            <table className="sticky-table table-fixed w-full min-w-[560px] text-left">
              <colgroup>
                <col style={{ width: 120 }} />
                <col style={{ width: 200 }} />
                <col style={{ width: 96 }} />
                <col />
              </colgroup>
              <thead>
                <tr>
                  <th className="col-sticky-left">{t("processes.colActions")}</th>
                  <th className="col-sticky-left-2" style={{ left: 120 }}>
                    {t("processes.colName")}
                  </th>
                  <th>{t("processes.colPid")}</th>
                  <th>{t("processes.colImagePath")}</th>
                </tr>
              </thead>
              <tbody>
              {listLoading && rows.length === 0
                ? Array.from({ length: 8 }).map((_, i) => (
                    <tr key={`pl-sk-${i}`}>
                      <td colSpan={4} className="px-4 py-2">
                        <Skeleton className="h-8 w-full" />
                      </td>
                    </tr>
                  ))
                : filteredRows.map((r) => (
                    <tr
                      key={r.pid}
                      className={`group ${r.ignored ? "opacity-60" : ""}`}
                    >
                      <td className="col-sticky-left">
                        <div className="flex justify-start gap-1 opacity-60 transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100">
                          <button
                            type="button"
                            disabled={r.pid === 0}
                            title={t("processes.endProcess")}
                            aria-label={t("processes.endProcess")}
                            onClick={(e) => {
                              e.stopPropagation();
                              setProcessActionModal({
                                pid: r.pid,
                                name: r.name,
                                variant: "kill",
                              });
                            }}
                            className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-(--muted) transition-colors duration-200 hover:bg-(--severity-high)/15 hover:text-(--severity-high) disabled:pointer-events-none disabled:opacity-40"
                          >
                            <Skull className="h-4 w-4" aria-hidden />
                          </button>
                          <button
                            type="button"
                            disabled={r.pid === 0}
                            title={t("processes.quarantine")}
                            aria-label={t("processes.quarantine")}
                            onClick={(e) => {
                              e.stopPropagation();
                              setProcessActionModal({
                                pid: r.pid,
                                name: r.name,
                                variant: "quarantine",
                              });
                            }}
                            className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-(--muted) transition-colors duration-200 hover:bg-(--severity-high)/15 hover:text-(--severity-high) disabled:pointer-events-none disabled:opacity-40"
                          >
                            <ShieldOff className="h-4 w-4" aria-hidden />
                          </button>
                          {!r.ignored ? (
                            <button
                              type="button"
                              disabled={!r.exePath}
                              title={t("processes.actions.ignore")}
                              aria-label={t("processes.actions.ignore")}
                              onClick={(e) => {
                                e.stopPropagation();
                                if (!r.exePath) return;
                                setIgnoreModal({
                                  imagePath: r.exePath,
                                  name: r.name,
                                });
                              }}
                              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-(--muted) transition-colors duration-200 hover:bg-(--accent)/15 hover:text-(--accent) disabled:pointer-events-none disabled:opacity-40"
                            >
                              <EyeOff className="h-4 w-4" aria-hidden />
                            </button>
                          ) : null}
                        </div>
                      </td>
                      <td className="col-sticky-left-2 min-w-0" style={{ left: 120 }}>
                        <div className="flex min-w-0 flex-nowrap items-center gap-2">
                          <span className="min-w-0 truncate" title={r.name}>
                            {r.name}
                          </span>
                          {r.ignored ? (
                            <span className="shrink-0 rounded-full border border-(--border) bg-(--surface-2)/70 px-2 py-0.5 text-[10px] font-medium text-(--muted)">
                              {t("processes.badges.ignored")}
                            </span>
                          ) : null}
                          {r.ignored && r.exePath ? (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                void unignorePath(r.exePath!);
                              }}
                              className="shrink-0 text-xs font-medium text-(--accent) opacity-0 transition-opacity duration-200 hover:underline group-hover:opacity-100"
                            >
                              {t("processes.actions.unignore")}
                            </button>
                          ) : null}
                        </div>
                      </td>
                      <td className="font-mono tabular-nums">{r.pid}</td>
                      <TruncCell
                        value={r.exePath ?? ""}
                        className="font-mono text-xs text-(--muted)"
                      />
                    </tr>
                  ))}
            </tbody>
          </table>
          </StickyTable>
          {!listLoading && filteredRows.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-(--muted)">
              {rows.length === 0
                ? t("processes.noProcesses")
                : t("processes.noFilterMatches")}
            </div>
          ) : null}
        </div>
      </div>

      <AnimatePresence>
        {selected ? (
          <ProcessDrawer
            key={selected.pid}
            selected={selected}
            warnAt={thresholds.warnThreshold}
            alertAt={thresholds.alertThreshold}
            onClose={() => setSelected(null)}
            onProcessesChanged={refreshAfterDanger}
          />
        ) : null}
      </AnimatePresence>

      <ProcessActionModal
        open={processActionModal !== null}
        variant={processActionModal?.variant ?? "kill"}
        pid={processActionModal?.pid ?? 0}
        fallbackName={processActionModal?.name ?? ""}
        onClose={() => setProcessActionModal(null)}
        onCompleted={refreshAfterDanger}
      />

      <IgnoreActionModal
        open={ignoreModal !== null}
        imagePath={ignoreModal?.imagePath ?? ""}
        processName={ignoreModal?.name ?? ""}
        onClose={() => setIgnoreModal(null)}
        onCompleted={() => {
          void loadLatest();
          void loadProcesses();
        }}
      />
    </div>
  );
}
