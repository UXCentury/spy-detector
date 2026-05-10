"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { StickyNote } from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  startTransition,
} from "react";
import { ScoreGauge } from "@/components/ScoreGauge";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { Toggle } from "@/components/Toggle";
import { useToast } from "@/components/Toast";
import { useScanCompleted } from "@/lib/hooks/useScanCompleted";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type { StartupEntry } from "@/lib/types";

const GAUGE_WARN = 60;
const GAUGE_ALERT = 75;

type SevFilter = "all" | "high" | "warn" | "low";
type SrcFilter = "all" | "registry" | "folder" | "tasks";

function sourceKey(s: StartupEntry["source"]): StringKey {
  const m: Record<StartupEntry["source"], StringKey> = {
    "hkcu-run": "startup.source.hkcuRun",
    "hkcu-run-once": "startup.source.hkcuRunOnce",
    "hklm-run": "startup.source.hklmRun",
    "hklm-run-once": "startup.source.hklmRunOnce",
    "hklm-wow64-run": "startup.source.hklmWow64Run",
    "startup-folder-user": "startup.source.startupFolderUser",
    "startup-folder-all-users": "startup.source.startupFolderAllUsers",
    "task-scheduler": "startup.source.taskScheduler",
  };
  return m[s];
}

function scopeKey(s: StartupEntry["scope"]): StringKey {
  const m: Record<StartupEntry["scope"], StringKey> = {
    "current-user": "startup.scope.currentUser",
    "all-users": "startup.scope.allUsers",
    system: "startup.scope.system",
  };
  return m[s];
}

function isRegistrySource(src: StartupEntry["source"]): boolean {
  return (
    src === "hkcu-run" ||
    src === "hkcu-run-once" ||
    src === "hklm-run" ||
    src === "hklm-run-once" ||
    src === "hklm-wow64-run"
  );
}

export default function StartupPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [rows, setRows] = useState<StartupEntry[]>([]);
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
  const [sev, setSev] = useState<SevFilter>("all");
  const [src, setSrc] = useState<SrcFilter>("all");
  const [selected, setSelected] = useState<StartupEntry | null>(null);
  const [noteDraft, setNoteDraft] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await invoke<StartupEntry[]>("list_startup_entries");
      if (!mountedRef.current) return;
      setRows(list);
    } catch (e) {
      console.error("[startup] ipc failed", e);
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

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await invoke<StartupEntry[]>("refresh_startup_entries");
      if (!mountedRef.current) return;
      setRows(list);
    } catch (e) {
      console.error("[startup] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      if (!mountedRef.current) return;
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    let cancelled = false;
    startTransition(() => {
      void (async () => {
        setLoading(true);
        try {
          const list = await invoke<StartupEntry[]>("list_startup_entries");
          if (cancelled) return;
          setRows(list);
        } catch (e) {
          console.error("[startup] ipc failed", e);
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

  const counts = useMemo(() => {
    let high = 0;
    let warn = 0;
    let low = 0;
    let info = 0;
    for (const r of rows) {
      if (r.severity === "high") high += 1;
      else if (r.severity === "warn") warn += 1;
      else if (r.severity === "low") low += 1;
      else info += 1;
    }
    return { high, warn, low, info, total: rows.length };
  }, [rows]);

  const filtered = useMemo(() => {
    return rows
      .filter((r) => {
        if (sev === "high" && r.severity !== "high") return false;
        if (sev === "warn" && r.severity !== "warn") return false;
        if (sev === "low" && r.severity !== "low" && r.severity !== "info")
          return false;
        if (src === "registry" && !isRegistrySource(r.source)) return false;
        if (
          src === "folder" &&
          r.source !== "startup-folder-user" &&
          r.source !== "startup-folder-all-users"
        )
          return false;
        if (src === "tasks" && r.source !== "task-scheduler") return false;
        return true;
      })
      .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  }, [rows, sev, src]);

  const chip = (active: boolean, on: () => void, label: string) => (
    <button
      type="button"
      onClick={on}
      className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-200 ${
        active
          ? "border-(--accent) bg-(--accent)/20 text-(--foreground)"
          : "border-(--border) bg-(--surface-2)/40 text-(--muted) hover:border-(--border-bright)"
      }`}
    >
      {label}
    </button>
  );

  const onToggleEnabled = async (entry: StartupEntry, enabled: boolean) => {
    try {
      await invoke("set_startup_entry_enabled", { id: entry.id, enabled });
      if (!mountedRef.current) return;
      showToast(
        enabled ? t("startup.toast.enabled") : t("startup.toast.disabled"),
        "success",
      );
      await refresh();
      if (!mountedRef.current) return;
      setSelected((s) =>
        s?.id === entry.id ? { ...s, enabled } : s,
      );
    } catch (e) {
      console.error("[startup] ipc failed", e);
      if (!mountedRef.current) return;
      const msg = e instanceof Error ? e.message : String(e);
      showToast(t("startup.toast.disableFailed").replace("{error}", msg), "error");
    }
  };

  const saveNote = async () => {
    if (!selected) return;
    try {
      const note = noteDraft.trim() === "" ? null : noteDraft.trim();
      await invoke("set_startup_entry_note", { id: selected.id, note });
      if (!mountedRef.current) return;
      showToast(t("startup.toast.noteSaved"), "success");
      await refresh();
      if (!mountedRef.current) return;
      setSelected((s) => (s?.id === selected.id ? { ...s, note } : s));
    } catch (e) {
      console.error("[startup] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  return (
    <div className="relative space-y-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("startup.title")}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-(--muted)">
            {t("startup.subtitle")}
          </p>
        </div>
        <button
          type="button"
          disabled={loading}
          onClick={() => void refresh()}
          className="shrink-0 rounded-lg border border-(--border) bg-(--surface-2)/60 px-4 py-2 text-sm font-medium text-(--foreground) transition-colors hover:bg-(--surface-2) disabled:opacity-50"
        >
          {t("startup.refresh")}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs text-(--muted)">
        <span>{t("startup.meta.count").replace("{count}", String(counts.total))}</span>
        <span className="text-(--severity-high)">
          {counts.high} {t("processes.filterHigh")}
        </span>
        <span className="text-(--severity-warn)">
          {counts.warn} {t("processes.filterWarn")}
        </span>
        <span>
          {counts.low + counts.info} {t("startup.filter.low")}
        </span>
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap gap-2">
          {chip(sev === "all", () => setSev("all"), t("processes.filterAll"))}
          {chip(sev === "high", () => setSev("high"), t("processes.filterHigh"))}
          {chip(sev === "warn", () => setSev("warn"), t("processes.filterWarn"))}
          {chip(sev === "low", () => setSev("low"), t("startup.filter.low"))}
        </div>
        <div className="flex flex-wrap gap-2">
          {chip(src === "all", () => setSrc("all"), t("startup.sourceFilter.all"))}
          {chip(
            src === "registry",
            () => setSrc("registry"),
            t("startup.sourceFilter.registry"),
          )}
          {chip(src === "folder", () => setSrc("folder"), t("startup.sourceFilter.folder"))}
          {chip(src === "tasks", () => setSrc("tasks"), t("startup.sourceFilter.tasks"))}
        </div>
      </div>

      {loading && rows.length === 0 ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-(--border) bg-(--surface)/60 px-6 py-12 text-center">
          <p className="text-base font-medium text-(--foreground)">{t("startup.empty.title")}</p>
          <p className="mt-2 text-sm text-(--muted)">{t("startup.empty.body")}</p>
        </div>
      ) : (
        <StickyTable>
          <table className="sticky-table min-w-[720px] text-left">
            <colgroup>
              <col style={{ width: 80 }} />
              <col style={{ width: 220 }} />
              <col style={{ minWidth: 120 }} />
              <col style={{ minWidth: 100 }} />
              <col style={{ width: "32%", minWidth: 240 }} />
              <col style={{ minWidth: 88 }} />
              <col style={{ width: "28%" }} />
              <col style={{ width: 108 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left">{t("startup.cols.score")}</th>
                <th className="col-sticky-left-2">
                  {t("startup.cols.name")}
                </th>
                <th>{t("startup.cols.source")}</th>
                <th>{t("startup.cols.scope")}</th>
                <th>{t("startup.cols.path")}</th>
                <th>{t("startup.cols.signed")}</th>
                <th>{t("startup.cols.reasons")}</th>
                <th className="col-sticky-right text-right">{t("startup.cols.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => {
                const reasonsJoined = r.reasons.join(", ");
                const pathTitle = [r.imagePath, r.command].filter(Boolean).join("\n");
                return (
                  <tr
                    key={r.id}
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
                    <td className="col-sticky-left-2 font-medium text-(--foreground)">
                      {r.name}
                    </td>
                    <td className="text-(--muted)">{t(sourceKey(r.source))}</td>
                    <td className="text-(--muted)">{t(scopeKey(r.scope))}</td>
                    <TruncCell
                      value={r.imagePath ?? ""}
                      title={pathTitle || undefined}
                      className="text-(--muted)"
                    />
                    <td className="text-(--muted)">
                      {r.signed === true
                        ? t("startup.signed.yes")
                        : r.signed === false
                          ? t("startup.signed.no")
                          : t("startup.signed.unknown")}
                    </td>
                    <TruncCell value={reasonsJoined} className="text-(--muted)" />
                    <td className="col-sticky-right text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5 whitespace-nowrap">
                        <button
                          type="button"
                          title={t("startup.action.note")}
                          aria-label={t("startup.action.note")}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-(--border) text-(--muted) hover:bg-(--surface-2)"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(r);
                            setNoteDraft(r.note ?? "");
                          }}
                        >
                          <StickyNote className="size-3.5" aria-hidden />
                        </button>
                        <Toggle
                          checked={r.enabled}
                          disabled={!r.canDisable}
                          title={
                            !r.canDisable
                              ? t("services.action.requiresAdmin")
                              : r.enabled
                                ? t("startup.action.disable")
                                : t("startup.action.enable")
                          }
                          ariaLabel={t("startup.cols.actions")}
                          onChange={(next) => void onToggleEnabled(r, next)}
                        />
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
                <h2 className="text-lg font-semibold">{selected.name}</h2>
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
                    <div>{t(sourceKey(selected.source))}</div>
                    <div>{t(scopeKey(selected.scope))}</div>
                  </div>
                </div>
                <div>
                  <div className="text-xs font-medium uppercase text-(--muted)">
                    {t("startup.field.command")}
                  </div>
                  <pre className="mt-1 whitespace-pre-wrap break-all rounded-lg bg-(--surface-2)/50 p-3 text-xs text-(--foreground)">
                    {selected.command}
                  </pre>
                </div>
                {selected.imagePath ? (
                  <div>
                    <div className="text-xs font-medium uppercase text-(--muted)">
                      {t("startup.cols.path")}
                    </div>
                    <p className="mt-1 break-all text-sm text-(--foreground)">{selected.imagePath}</p>
                  </div>
                ) : null}
                <div>
                  <div className="text-xs font-medium uppercase text-(--muted)">
                    {t("startup.field.reasons")}
                  </div>
                  <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-(--foreground)">
                    {selected.reasons.length === 0 ? (
                      <li className="text-(--muted)">—</li>
                    ) : (
                      selected.reasons.map((x) => <li key={x}>{x}</li>)
                    )}
                  </ul>
                </div>
                <div>
                  <label className="text-xs font-medium uppercase text-(--muted)" htmlFor="startup-note">
                    {t("startup.action.note")}
                  </label>
                  <textarea
                    id="startup-note"
                    value={noteDraft}
                    onChange={(e) => setNoteDraft(e.target.value)}
                    rows={4}
                    className="mt-2 w-full rounded-lg border border-(--border) bg-(--surface-2)/40 px-3 py-2 text-sm text-(--foreground)"
                  />
                  <button
                    type="button"
                    className="mt-2 rounded-lg border border-(--accent) bg-(--accent)/15 px-4 py-2 text-sm font-medium"
                    onClick={() => void saveNote()}
                  >
                    {t("common.save")}
                  </button>
                </div>
                <div className="flex items-center gap-2 border-t border-(--border) pt-4">
                  <Toggle
                    checked={selected.enabled}
                    disabled={!selected.canDisable}
                    title={
                      !selected.canDisable
                        ? t("services.action.requiresAdmin")
                        : undefined
                    }
                    label={selected.enabled ? t("startup.action.disable") : t("startup.action.enable")}
                    onChange={(next) => void onToggleEnabled(selected, next)}
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
