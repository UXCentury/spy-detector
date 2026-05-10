"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, Play, Square, StickyNote } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, startTransition } from "react";
import { ProgressBar } from "@/components/ProgressBar";
import { ScoreGauge } from "@/components/ScoreGauge";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { Toggle } from "@/components/Toggle";
import { useToast } from "@/components/Toast";
import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import { useScanCompleted } from "@/lib/hooks/useScanCompleted";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type { ServiceEntry } from "@/lib/types";

const GAUGE_WARN = 60;
const GAUGE_ALERT = 75;

type SvcFilter =
  | "all"
  | "high"
  | "warn"
  | "running"
  | "stopped"
  | "auto"
  | "disabled";

function startTypeLabelKey(st: string): StringKey | null {
  switch (st) {
    case "AutoStart":
      return "services.startType.autoStart";
    case "BootStart":
      return "services.startType.bootStart";
    case "SystemStart":
      return "services.startType.systemStart";
    case "DemandStart":
      return "services.startType.demandStart";
    case "Disabled":
      return "services.startType.disabled";
    default:
      return null;
  }
}

function statusLabelKey(st: string): StringKey | null {
  switch (st) {
    case "Running":
      return "services.status.running";
    case "Stopped":
      return "services.status.stopped";
    case "Paused":
      return "services.status.paused";
    case "StartPending":
      return "services.status.startPending";
    case "StopPending":
      return "services.status.stopPending";
    default:
      return null;
  }
}

function isAutoStart(st: string): boolean {
  return st === "AutoStart" || st === "BootStart" || st === "SystemStart";
}

export default function ServicesPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const { tick } = useMonitoringTick();
  const elevated = tick?.elevated ?? false;
  const [rows, setRows] = useState<ServiceEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [navPrimed, setNavPrimed] = useState(false);
  const navOnce = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);
  const [filter, setFilter] = useState<SvcFilter>("all");
  const [selected, setSelected] = useState<ServiceEntry | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [restartBusy, setRestartBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await invoke<ServiceEntry[]>("list_services");
      if (!mountedRef.current) return;
      setRows(list);
    } catch (e) {
      console.error("[services] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      if (!mountedRef.current) return;
      setLoading(false);
      if (!navOnce.current) {
        navOnce.current = true;
        setNavPrimed(true);
      }
    }
  }, [showToast]);

  useEffect(() => {
    let cancelled = false;
    startTransition(() => {
      void (async () => {
        setLoading(true);
        try {
          const list = await invoke<ServiceEntry[]>("list_services");
          if (cancelled) return;
          setRows(list);
        } catch (e) {
          console.error("[services] ipc failed", e);
          if (cancelled) return;
          showToast(e instanceof Error ? e.message : String(e), "error");
        } finally {
          if (!cancelled) {
            setLoading(false);
            if (!navOnce.current) {
              navOnce.current = true;
              setNavPrimed(true);
            }
          }
        }
      })();
    });
    return () => {
      cancelled = true;
    };
  }, [showToast]);

  usePageReady(navPrimed);

  useScanCompleted(() => {
    void load();
  });

  useEffect(() => {
    if (!selected) return;
    startTransition(() => {
      setNoteDraft(selected.note ?? "");
    });
  }, [selected]);

  const filtered = useMemo(() => {
    return rows
      .filter((r) => {
        if (filter === "high" && r.severity !== "high") return false;
        if (filter === "warn" && r.severity !== "warn") return false;
        if (filter === "running" && r.status !== "Running") return false;
        if (filter === "stopped" && r.status !== "Stopped") return false;
        if (filter === "auto" && !isAutoStart(r.startType)) return false;
        if (filter === "disabled" && r.startType !== "Disabled") return false;
        return true;
      })
      .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  }, [rows, filter]);

  const chip = (id: SvcFilter, label: string) => (
    <button
      type="button"
      onClick={() => setFilter(id)}
      className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-200 ${
        filter === id
          ? "border-(--accent) bg-(--accent)/20 text-(--foreground)"
          : "border-(--border) bg-(--surface-2)/40 text-(--muted) hover:border-(--border-bright)"
      }`}
    >
      {label}
    </button>
  );

  const runElevated = async () => {
    setRestartBusy(true);
    try {
      await invoke("request_elevation_restart");
    } catch (e) {
      console.error("[services] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
      setRestartBusy(false);
    }
  };

  const onSetAuto = async (entry: ServiceEntry, enabled: boolean) => {
    try {
      await invoke("set_service_enabled", { name: entry.name, enabled });
      if (!mountedRef.current) return;
      showToast(t("services.toast.startTypeChanged"), "success");
      await load();
    } catch (e) {
      console.error("[services] ipc failed", e);
      if (!mountedRef.current) return;
      const msg = e instanceof Error ? e.message : String(e);
      showToast(t("services.toast.failed").replace("{error}", msg), "error");
    }
  };

  const onStart = async (name: string) => {
    try {
      await invoke("start_service_cmd", { name });
      if (!mountedRef.current) return;
      showToast(t("services.toast.started"), "success");
      await load();
    } catch (e) {
      console.error("[services] ipc failed", e);
      if (!mountedRef.current) return;
      const msg = e instanceof Error ? e.message : String(e);
      showToast(t("services.toast.failed").replace("{error}", msg), "error");
    }
  };

  const onStop = async (name: string) => {
    try {
      await invoke("stop_service_cmd", { name });
      if (!mountedRef.current) return;
      showToast(t("services.toast.stopped"), "success");
      await load();
    } catch (e) {
      console.error("[services] ipc failed", e);
      if (!mountedRef.current) return;
      const msg = e instanceof Error ? e.message : String(e);
      showToast(t("services.toast.failed").replace("{error}", msg), "error");
    }
  };

  const saveNote = async () => {
    if (!selected) return;
    try {
      const note = noteDraft.trim() === "" ? null : noteDraft.trim();
      await invoke("set_service_note", { name: selected.name, note });
      if (!mountedRef.current) return;
      showToast(t("services.toast.noteSaved"), "success");
      await load();
    } catch (e) {
      console.error("[services] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const protectionTitle = (r: ServiceEntry): string | undefined => {
    if (r.isCritical) return t("services.action.criticalProtected");
    if (r.isMicrosoft) return t("services.action.microsoftProtected");
    return undefined;
  };

  const rowActionTitle = (r: ServiceEntry): string | undefined => {
    if (!elevated) return t("services.action.requiresAdmin");
    if (!r.canDisable) return protectionTitle(r);
    return undefined;
  };

  const mutationsLocked = !elevated;

  return (
    <div className="relative space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("services.title")}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-(--muted)">
            {t("services.subtitle")}
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-stretch gap-2 sm:items-end">
          <button
            type="button"
            disabled={loading}
            onClick={() => void load()}
            className="rounded-lg border border-(--border) bg-(--surface-2)/60 px-4 py-2 text-sm font-medium text-(--foreground) transition-colors hover:bg-(--surface-2) disabled:opacity-50"
          >
            {t("services.refresh")}
          </button>
          {mutationsLocked ? (
            <button
              type="button"
              disabled={restartBusy}
              onClick={() => void runElevated()}
              className="rounded-lg border border-(--severity-warn)/50 bg-(--surface)/80 px-3 py-2 text-xs font-medium text-(--foreground) hover:bg-(--surface-2) disabled:opacity-60"
            >
              {restartBusy ? t("elevation.starting") : t("elevation.restartButton")}
            </button>
          ) : null}
          {restartBusy ? <ProgressBar className="w-40" /> : null}
        </div>
      </div>

      <div className="text-xs text-(--muted)">
        {t("services.meta.count").replace("{count}", String(rows.length))}
      </div>

      <div className="flex flex-wrap gap-2">
        {chip("all", t("services.filter.all"))}
        {chip("high", t("services.filter.high"))}
        {chip("warn", t("services.filter.warn"))}
        {chip("running", t("services.filter.running"))}
        {chip("stopped", t("services.filter.stopped"))}
        {chip("auto", t("services.filter.autoStart"))}
        {chip("disabled", t("services.filter.disabled"))}
      </div>

      {loading && rows.length === 0 ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-(--border) bg-(--surface)/60 px-6 py-12 text-center">
          <p className="text-base font-medium text-(--foreground)">{t("services.empty.title")}</p>
          <p className="mt-2 text-sm text-(--muted)">{t("services.empty.body")}</p>
        </div>
      ) : (
        <StickyTable>
          <table className="sticky-table min-w-[960px] text-left">
            <colgroup>
              <col style={{ width: 80 }} />
              <col style={{ width: 200 }} />
              <col style={{ width: "22%" }} />
              <col style={{ minWidth: 96 }} />
              <col style={{ minWidth: 120 }} />
              <col style={{ width: "24%" }} />
              <col style={{ minWidth: 88 }} />
              <col style={{ width: "18%" }} />
              <col style={{ width: 136 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left">{t("services.cols.score")}</th>
                <th className="col-sticky-left-2">
                  {t("services.cols.name")}
                </th>
                <th>{t("services.cols.displayName")}</th>
                <th>{t("services.cols.status")}</th>
                <th>{t("services.cols.startType")}</th>
                <th>{t("services.cols.path")}</th>
                <th>{t("services.cols.signed")}</th>
                <th>{t("services.cols.account")}</th>
                <th className="col-sticky-right text-right">{t("services.cols.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => {
                const protectedRow = !r.canDisable && (r.isCritical || r.isMicrosoft);
                const autoOn = isAutoStart(r.startType);
                return (
                  <tr
                    key={r.name}
                    className="cursor-pointer"
                    onClick={() => setSelected(r)}
                  >
                    <td className="col-sticky-left align-middle">
                      <ScoreGauge
                        score={r.score}
                        warnThreshold={GAUGE_WARN}
                        alertThreshold={GAUGE_ALERT}
                        size="sm"
                        animate={false}
                      />
                    </td>
                    <td className="col-sticky-left-2 font-mono text-xs text-(--foreground)">
                      {r.name}
                    </td>
                    <TruncCell value={r.displayName} className="text-(--foreground)" />
                    <td className="text-(--muted)">
                      {statusLabelKey(r.status) ? t(statusLabelKey(r.status)!) : r.status}
                    </td>
                    <td className="text-(--muted)">
                      {(() => {
                        const k = startTypeLabelKey(r.startType);
                        return k ? t(k) : r.startType;
                      })()}
                    </td>
                    <TruncCell value={r.binaryPath ?? ""} className="font-mono text-(--muted)" />
                    <td className="text-(--muted)">
                      {r.signed === true
                        ? t("startup.signed.yes")
                        : r.signed === false
                          ? t("startup.signed.no")
                          : t("startup.signed.unknown")}
                    </td>
                    <TruncCell value={r.account ?? ""} className="text-(--muted)" />
                    <td className="col-sticky-right text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5 whitespace-nowrap">
                        {protectedRow ? (
                          <span className="inline-flex items-center text-(--severity-warn)" title={protectionTitle(r)}>
                            <AlertTriangle className="size-4 shrink-0" aria-hidden />
                          </span>
                        ) : null}
                        <button
                          type="button"
                          title={t("services.action.note")}
                          aria-label={t("services.action.note")}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-(--border) text-(--muted) hover:bg-(--surface-2)"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(r);
                            setNoteDraft(r.note ?? "");
                          }}
                        >
                          <StickyNote className="size-3.5" aria-hidden />
                        </button>
                        <button
                          type="button"
                          disabled={mutationsLocked || !r.canDisable || r.status === "Running"}
                          title={rowActionTitle(r) ?? t("services.action.start")}
                          aria-label={t("services.action.start")}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-(--border) text-(--muted) hover:bg-(--surface-2) hover:text-(--severity-low) disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-(--muted)"
                          onClick={(e) => {
                            e.stopPropagation();
                            void onStart(r.name);
                          }}
                        >
                          <Play className="size-3.5" aria-hidden />
                        </button>
                        <button
                          type="button"
                          disabled={mutationsLocked || !r.canDisable || r.status !== "Running"}
                          title={rowActionTitle(r) ?? t("services.action.stop")}
                          aria-label={t("services.action.stop")}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-(--border) text-(--muted) hover:bg-(--surface-2) hover:text-(--severity-high) disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-(--muted)"
                          onClick={(e) => {
                            e.stopPropagation();
                            void onStop(r.name);
                          }}
                        >
                          <Square className="size-3.5" aria-hidden />
                        </button>
                        <span title={rowActionTitle(r) ?? t("services.action.autoStart")} className="inline-flex">
                          <Toggle
                            checked={autoOn}
                            disabled={mutationsLocked || !r.canDisable}
                            ariaLabel={t("services.action.autoStart")}
                            onChange={(next) => void onSetAuto(r, next)}
                          />
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </StickyTable>
      )}

      <AnimatePresence>
        {selected ? (
          <>
            <motion.button
              type="button"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-40 bg-black/50"
              aria-label={t("common.close")}
              onClick={() => setSelected(null)}
            />
            <motion.aside
              role="dialog"
              aria-modal
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{ type: "spring", stiffness: 380, damping: 36 }}
              className="fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col border-l border-(--border) bg-(--surface) shadow-xl"
            >
              <div className="flex items-center justify-between border-b border-(--border) px-4 py-3">
                <div>
                  <h2 className="text-lg font-semibold">{selected.displayName}</h2>
                  <p className="font-mono text-xs text-(--muted)">{selected.name}</p>
                </div>
                <button
                  type="button"
                  className="rounded-md px-2 py-1 text-sm text-(--muted) hover:bg-(--surface-2)"
                  onClick={() => setSelected(null)}
                >
                  {t("common.close")}
                </button>
              </div>
              <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
                <div className="flex items-center gap-3">
                  <ScoreGauge
                    score={selected.score}
                    warnThreshold={GAUGE_WARN}
                    alertThreshold={GAUGE_ALERT}
                    size="md"
                  />
                  <div className="text-xs text-(--muted)">
                    <div>
                      {statusLabelKey(selected.status)
                        ? t(statusLabelKey(selected.status)!)
                        : selected.status}
                    </div>
                    <div>
                      {(() => {
                        const k = startTypeLabelKey(selected.startType);
                        return k ? t(k) : selected.startType;
                      })()}
                    </div>
                  </div>
                </div>
                {selected.binaryPath ? (
                  <div>
                    <div className="text-xs font-medium uppercase text-(--muted)">
                      {t("services.cols.path")}
                    </div>
                    <p className="mt-1 break-all text-sm">{selected.binaryPath}</p>
                  </div>
                ) : null}
                <div>
                  <div className="text-xs font-medium uppercase text-(--muted)">
                    {t("startup.field.reasons")}
                  </div>
                  <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
                    {selected.reasons.length === 0 ? (
                      <li className="text-(--muted)">—</li>
                    ) : (
                      selected.reasons.map((x) => <li key={x}>{x}</li>)
                    )}
                  </ul>
                </div>
                <div>
                  <label className="text-xs font-medium uppercase text-(--muted)" htmlFor="svc-note">
                    {t("services.action.note")}
                  </label>
                  <textarea
                    id="svc-note"
                    value={noteDraft}
                    onChange={(e) => setNoteDraft(e.target.value)}
                    rows={4}
                    className="mt-2 w-full rounded-lg border border-(--border) bg-(--surface-2)/40 px-3 py-2 text-sm"
                  />
                  <button
                    type="button"
                    className="mt-2 rounded-lg border border-(--accent) bg-(--accent)/15 px-4 py-2 text-sm font-medium"
                    onClick={() => void saveNote()}
                  >
                    {t("common.save")}
                  </button>
                </div>
                <div className="flex flex-wrap gap-3 border-t border-(--border) pt-4">
                  <button
                    type="button"
                    disabled={mutationsLocked || !selected.canDisable}
                    title={rowActionTitle(selected) ?? t("services.action.start")}
                    className="rounded-lg border border-(--border) px-3 py-2 text-sm disabled:opacity-50"
                    onClick={() => void onStart(selected.name)}
                  >
                    {t("services.action.start")}
                  </button>
                  <button
                    type="button"
                    disabled={mutationsLocked || !selected.canDisable}
                    title={rowActionTitle(selected) ?? t("services.action.stop")}
                  >
                    {t("services.action.stop")}
                  </button>
                  <Toggle
                    checked={isAutoStart(selected.startType)}
                    disabled={mutationsLocked || !selected.canDisable}
                    title={rowActionTitle(selected)}
                    onChange={(next) => void onSetAuto(selected, next)}
                  />
                </div>
              </div>
            </motion.aside>
          </>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
