"use client";

import { invoke } from "@tauri-apps/api/core";
import { Copy, Eraser, Loader2, ShieldX, Trash2 } from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  startTransition,
} from "react";
import { SeverityDonut } from "@/components/SeverityDonut";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { useToast } from "@/components/Toast";
import { formatRelativeTime } from "@/lib/formatRelativeTime";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type {
  BrowserHistoryDeleteSummary,
  BrowserHistoryScanResult,
  CloseBrowserResult,
  HistoryFinding,
} from "@/lib/types";

const BH_CONFIRM_SKIP_KEY = "spy-detector-browser-history-skip-confirm";

const PAGE_SIZE = 100;
/** Cap rows fetched from SQLite (ORDER BY last_visit_at DESC). */
const MAX_BUFFERED = 500;

type SevFilter = "all" | "high" | "warn" | "low";
type CatFilter =
  | "all"
  | "github"
  | "paste"
  | "ipfs"
  | "discord"
  | "fileshare"
  | "stalkerware";

type PendingBrowserDelete =
  | { kind: "ids"; ids: number[] }
  | { kind: "all" };

type PendingRetry = { mode: "ids"; ids: number[] } | { mode: "all" };

type DeleteFlowState =
  | { stage: "idle" }
  | { stage: "confirm"; pending: PendingBrowserDelete }
  | { stage: "browser-running"; pending: PendingBrowserDelete; browser: string }
  | { stage: "closing"; pending: PendingBrowserDelete; browser: string; force: boolean }
  | { stage: "unresponsive"; pending: PendingBrowserDelete; browser: string }
  | { stage: "deleting"; pending: PendingBrowserDelete };

function severityBadgeClass(sev: string): string {
  switch (sev) {
    case "high":
      return "border border-(--severity-high)/40 bg-(--severity-high)/15 text-(--severity-high)";
    case "warn":
      return "border border-(--severity-warn)/40 bg-(--severity-warn)/15 text-(--severity-warn)";
    case "low":
      return "border border-(--severity-low)/40 bg-(--severity-low)/15 text-(--severity-low)";
    default:
      return "border border-(--border) bg-(--surface-2) text-(--muted)";
  }
}

function severityLabelKey(sev: string): StringKey {
  if (sev === "info") return "logs.severity.info";
  if (sev === "low") return "logs.severity.low";
  if (sev === "warn") return "logs.severity.warn";
  return "logs.severity.high";
}

function categoryChipClass(cat: string): string {
  if (cat === "abuse-ch-urlhaus" || cat === "abuse-ch-threatfox") {
    return "inline-flex rounded-md border border-(--severity-high)/35 bg-(--severity-high)/12 px-1.5 py-0.5 text-[10px] text-(--severity-high)";
  }
  return "inline-flex rounded-md border border-(--border) bg-(--surface-2) px-1.5 py-0.5 text-[10px] text-(--foreground)";
}

function categoryBadgeLabelKey(cat: string): StringKey | null {
  switch (cat) {
    case "github-malicious":
      return "devInfra.categories.githubMalicious";
    case "github-offensive":
      return "devInfra.categories.githubOffensive";
    case "paste":
      return "devInfra.categories.paste";
    case "ipfs":
      return "devInfra.categories.ipfs";
    case "discord-cdn":
      return "devInfra.categories.discordCdn";
    case "telegram-cdn":
      return "devInfra.categories.telegramCdn";
    case "shortener":
      return "devInfra.categories.shortener";
    case "file-share":
      return "devInfra.categories.fileShare";
    case "suspicious-path":
      return "devInfra.categories.suspiciousPath";
    case "stalkerware":
      return "devInfra.categories.stalkerware";
    case "abuse-ch-urlhaus":
      return "browserHistory.categories.abuseChUrlhaus";
    case "abuse-ch-threatfox":
      return "browserHistory.categories.abuseChThreatfox";
    default:
      return null;
  }
}

function rowMatchesCategory(row: HistoryFinding, cat: CatFilter): boolean {
  if (cat === "all") return true;
  const m = row.matchedCategories;
  switch (cat) {
    case "github":
      return m.some((c) => c === "github-malicious" || c === "github-offensive");
    case "paste":
      return m.includes("paste");
    case "ipfs":
      return m.includes("ipfs");
    case "discord":
      return m.includes("discord-cdn");
    case "fileshare":
      return m.includes("file-share");
    case "stalkerware":
      return m.includes("stalkerware");
    default:
      return true;
  }
}

function uniqueBrowsersFromRows(rows: HistoryFinding[], ids: number[]): string {
  const idSet = new Set(ids);
  const names = new Set<string>();
  for (const r of rows) {
    if (idSet.has(r.id)) names.add(r.browser);
  }
  return [...names].sort().join(", ");
}

function allUniqueBrowsers(rows: HistoryFinding[]): string {
  const names = new Set(rows.map((r) => r.browser));
  return [...names].sort().join(", ");
}

const CAT_CHIPS: { id: CatFilter; labelKey: StringKey }[] = [
  { id: "all", labelKey: "activity.filters.all" },
  { id: "github", labelKey: "browserHistory.categories.github" },
  { id: "paste", labelKey: "devInfra.categories.paste" },
  { id: "ipfs", labelKey: "devInfra.categories.ipfs" },
  { id: "discord", labelKey: "devInfra.categories.discordCdn" },
  { id: "fileshare", labelKey: "devInfra.categories.fileShare" },
  { id: "stalkerware", labelKey: "devInfra.categories.stalkerware" },
];

export default function BrowserHistoryPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [rows, setRows] = useState<HistoryFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [sev, setSev] = useState<SevFilter>("all");
  const [cat, setCat] = useState<CatFilter>("all");
  const [lastScan, setLastScan] = useState<BrowserHistoryScanResult | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [deleteFlow, setDeleteFlow] = useState<DeleteFlowState>({ stage: "idle" });
  const [dontAskAgainBrowserDelete, setDontAskAgainBrowserDelete] = useState(false);
  const [lockedBannerVisible, setLockedBannerVisible] = useState(false);
  const [lastLockedBrowsers, setLastLockedBrowsers] = useState<string[]>([]);
  const [runningBannerVisible, setRunningBannerVisible] = useState(false);
  const [lastRunningBrowsers, setLastRunningBrowsers] = useState<string[]>([]);
  const [pendingRetry, setPendingRetry] = useState<PendingRetry | null>(null);
  const [showAfterScrubEmpty, setShowAfterScrubEmpty] = useState(false);
  const [browserDeleting, setBrowserDeleting] = useState(false);
  const headerCheckboxRef = useRef<HTMLInputElement>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const timeFmt = useMemo(
    () =>
      new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }),
    [],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      setLoading(true);
      try {
        const list = await invoke<HistoryFinding[]>("list_browser_history_findings", {
          limit: MAX_BUFFERED,
          offset: 0,
          severity: sev === "all" ? null : sev,
        });
        if (cancelled) return;
        setRows(list);
      } catch (e) {
        console.error("[browser-history] ipc failed", e);
        if (cancelled) return;
        setRows([]);
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sev]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await invoke<HistoryFinding[]>("list_browser_history_findings", {
        limit: MAX_BUFFERED,
        offset: 0,
        severity: sev === "all" ? null : sev,
      });
      if (!mountedRef.current) return;
      setRows(list);
    } catch (e) {
      console.error("[browser-history] ipc failed", e);
      if (!mountedRef.current) return;
      setRows([]);
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [sev]);

  usePageReady(!loading);

  const filtered = useMemo(
    () =>
      rows.filter(
        (r) => (sev === "all" || r.severity === sev) && rowMatchesCategory(r, cat),
      ),
    [rows, sev, cat],
  );

  const [page, setPage] = useState(0);
  const filterEpoch = useMemo(() => ({ sev, cat }), [sev, cat]);
  const [prevFilterEpoch, setPrevFilterEpoch] = useState(filterEpoch);
  if (prevFilterEpoch !== filterEpoch) {
    setPrevFilterEpoch(filterEpoch);
    setPage(0);
  }

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const slice = filtered.slice(
    safePage * PAGE_SIZE,
    safePage * PAGE_SIZE + PAGE_SIZE,
  );

  useEffect(() => {
    const allowed = new Set(filtered.map((r) => r.id));
    startTransition(() => {
      setSelectedIds((prev) => {
        const next = new Set<number>();
        prev.forEach((id) => {
          if (allowed.has(id)) next.add(id);
        });
        return next;
      });
    });
  }, [filtered]);

  const selectedOnPage = useMemo(
    () => filtered.filter((r) => selectedIds.has(r.id)),
    [filtered, selectedIds],
  );

  useEffect(() => {
    const el = headerCheckboxRef.current;
    if (!el) return;
    const n = filtered.length;
    const sel = selectedOnPage.length;
    el.indeterminate = sel > 0 && sel < n;
  }, [filtered.length, selectedOnPage.length]);

  const donutCounts = useMemo(() => {
    let low = 0;
    let warn = 0;
    let high = 0;
    for (const r of filtered) {
      if (r.severity === "high") high += 1;
      else if (r.severity === "warn") warn += 1;
      else low += 1;
    }
    return { low, warn, high };
  }, [filtered]);

  const sessionSkipConfirm = (): boolean => {
    try {
      return sessionStorage.getItem(BH_CONFIRM_SKIP_KEY) === "1";
    } catch {
      return false;
    }
  };

  const applyDeleteSummary = useCallback(
    (summary: BrowserHistoryDeleteSummary, attemptedRetry: PendingRetry | null) => {
      if (!mountedRef.current) return;
      setSelectedIds(new Set());
      if (summary.succeeded > 0) {
        setShowAfterScrubEmpty(true);
      }

      const locked = summary.lockedBrowsers.length > 0;
      const runningList = summary.runningBrowsers ?? [];

      if (locked && attemptedRetry) {
        setLastLockedBrowsers(summary.lockedBrowsers);
        setPendingRetry(attemptedRetry);
        setLockedBannerVisible(true);
      } else {
        setLockedBannerVisible(false);
        setPendingRetry(null);
        setLastLockedBrowsers([]);
      }

      const showRunningBanner =
        !locked &&
        runningList.length > 0 &&
        summary.succeeded === 0 &&
        attemptedRetry != null &&
        summary.attempted > 0;
      if (showRunningBanner) {
        setLastRunningBrowsers(runningList);
        setRunningBannerVisible(true);
      } else {
        setRunningBannerVisible(false);
        setLastRunningBrowsers([]);
      }

      const total = summary.attempted;
      if (total === 0) {
        showToast(t("browserHistory.toast.nothingToRemove"), "info");
        return;
      }

      const lockedNames = summary.lockedBrowsers.join(", ");

      if (locked) {
        showToast(
          summary.succeeded > 0 && summary.succeeded < total
            ? t("browserHistory.toast.partial")
                .replace("{ok}", String(summary.succeeded))
                .replace("{total}", String(total))
                .replace("{failed}", String(summary.failed))
                .replace("{browsers}", lockedNames)
            : t("browserHistory.toast.allFailed").replace("{browsers}", lockedNames),
          summary.succeeded > 0 && summary.succeeded < total ? "info" : "error",
        );
        return;
      }

      if (summary.succeeded === total) {
        showToast(
          t("browserHistory.toast.removed").replace("{count}", String(summary.succeeded)),
          "info",
        );
        return;
      }

      if (summary.succeeded > 0) {
        showToast(
          t("browserHistory.toast.partial")
            .replace("{ok}", String(summary.succeeded))
            .replace("{total}", String(total))
            .replace("{failed}", String(summary.failed))
            .replace("{browsers}", runningList.join(", ") || t("common.error")),
          "info",
        );
        return;
      }

      if (runningList.length > 0) {
        showToast(
          t("browserHistory.toast.runningHint").replace("{browsers}", runningList.join(", ")),
          "info",
        );
        return;
      }

      const firstErr = summary.outcomes.find((o) => o.error)?.error ?? t("common.error");
      showToast(firstErr, "error");
    },
    [showToast, t],
  );

  const runBrowserDeleteInner = useCallback(
    async (pending: PendingBrowserDelete) => {
      const attemptedRetry: PendingRetry | null =
        pending.kind === "all" ? { mode: "all" } : { mode: "ids", ids: [...pending.ids] };

      setBrowserDeleting(true);
      setDeleteFlow({ stage: "deleting", pending });
      try {
        const summary =
          pending.kind === "all"
            ? await invoke<BrowserHistoryDeleteSummary>("delete_all_browser_history_findings")
            : await invoke<BrowserHistoryDeleteSummary>("delete_browser_history_findings", {
                findingIds: pending.ids,
              });
        const running = summary.runningBrowsers ?? [];
        if (running.length > 0 && summary.attempted === 0) {
          setDeleteFlow({
            stage: "browser-running",
            pending,
            browser: running[0]!,
          });
          return;
        }
        setDeleteFlow({ stage: "idle" });
        applyDeleteSummary(summary, attemptedRetry);
      } catch (e) {
        console.error("[browser-history] ipc failed", e);
        setDeleteFlow({ stage: "idle" });
        showToast(e instanceof Error ? e.message : String(e), "error");
      } finally {
        setBrowserDeleting(false);
        await refresh();
      }
    },
    [applyDeleteSummary, refresh, showToast],
  );

  const attemptCloseBrowser = useCallback(
    async (pending: PendingBrowserDelete, browser: string, force: boolean) => {
      setBrowserDeleting(true);
      setDeleteFlow({ stage: "closing", pending, browser, force });
      try {
        const result = await invoke<CloseBrowserResult>("close_browser_safely_cmd", {
          browser,
          force,
        });
        if (result.error) {
          showToast(result.error, "error");
          setDeleteFlow({ stage: "idle" });
          return;
        }
        if (result.remainingPids.length === 0) {
          if (force) {
            showToast(
              t("browserHistory.toast.forceClosed").replace("{browser}", browser),
              "info",
            );
          } else {
            showToast(t("browserHistory.toast.closed").replace("{browser}", browser), "info");
          }
          setDeleteFlow({ stage: "deleting", pending });
          const summary =
            pending.kind === "all"
              ? await invoke<BrowserHistoryDeleteSummary>("delete_all_browser_history_findings")
              : await invoke<BrowserHistoryDeleteSummary>("delete_browser_history_findings", {
                  findingIds: pending.ids,
                });
          const running = summary.runningBrowsers ?? [];
          if (running.length > 0 && summary.attempted === 0) {
            setDeleteFlow({
              stage: "browser-running",
              pending,
              browser: running[0]!,
            });
            return;
          }
          setDeleteFlow({ stage: "idle" });
          const attemptedRetry: PendingRetry | null =
            pending.kind === "all" ? { mode: "all" } : { mode: "ids", ids: [...pending.ids] };
          applyDeleteSummary(summary, attemptedRetry);
        } else if (!force) {
          setDeleteFlow({ stage: "unresponsive", pending, browser });
        } else {
          showToast(
            t("browserHistory.toast.closeFailed")
              .replace("{browser}", browser)
              .replace("{count}", String(result.remainingPids.length)),
            "error",
          );
          setDeleteFlow({ stage: "idle" });
        }
      } catch (e) {
        console.error("[browser-history] ipc failed", e);
        showToast(e instanceof Error ? e.message : String(e), "error");
        setDeleteFlow({ stage: "idle" });
      } finally {
        setBrowserDeleting(false);
        await refresh();
      }
    },
    [applyDeleteSummary, refresh, showToast, t],
  );

  const requestBrowserDelete = useCallback(
    (pending: PendingBrowserDelete) => {
      if (sessionSkipConfirm()) {
        void runBrowserDeleteInner(pending);
        return;
      }
      setDontAskAgainBrowserDelete(false);
      setDeleteFlow({ stage: "confirm", pending });
    },
    [runBrowserDeleteInner],
  );

  const confirmBrowserDeleteRun = useCallback(async () => {
    if (deleteFlow.stage !== "confirm") return;
    if (dontAskAgainBrowserDelete) {
      try {
        sessionStorage.setItem(BH_CONFIRM_SKIP_KEY, "1");
      } catch {
        /* ignore */
      }
    }
    const { pending } = deleteFlow;
    await runBrowserDeleteInner(pending);
  }, [deleteFlow, dontAskAgainBrowserDelete, runBrowserDeleteInner]);

  const pendingModalBrowsers = useMemo(() => {
    if (deleteFlow.stage !== "confirm") return "";
    if (deleteFlow.pending.kind === "all") return allUniqueBrowsers(rows);
    return uniqueBrowsersFromRows(rows, deleteFlow.pending.ids);
  }, [deleteFlow, rows]);

  const pendingModalCount = useMemo(() => {
    if (deleteFlow.stage !== "confirm") return 0;
    if (deleteFlow.pending.kind === "all") return rows.length;
    return deleteFlow.pending.ids.length;
  }, [deleteFlow, rows.length]);

  const runScan = async () => {
    setScanning(true);
    setShowAfterScrubEmpty(false);
    try {
      const res = await invoke<BrowserHistoryScanResult>("scan_browser_history");
      if (!mountedRef.current) return;
      setLastScan(res);
      showToast(
        t("browserHistory.totalFound").replace("{count}", String(res.totalFindings)),
        "info",
      );
      await refresh();
    } catch (e) {
      console.error("[browser-history] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      if (mountedRef.current) {
        setScanning(false);
      }
    }
  };

  const confirmClearRun = async () => {
    try {
      await invoke("clear_browser_history_findings");
      if (!mountedRef.current) return;
      setConfirmClear(false);
      showToast(t("common.success"), "info");
      setShowAfterScrubEmpty(false);
      await refresh();
    } catch (e) {
      console.error("[browser-history] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const copyUrl = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      showToast(t("common.copied"), "info");
    } catch {
      showToast(t("common.error"), "error");
    }
  };

  const toggleSelectAllFiltered = () => {
    const n = filtered.length;
    const sel = selectedOnPage.length;
    if (n === 0) return;
    if (sel === n) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((r) => r.id)));
    }
  };

  const toggleRowSelected = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const lockedBannerLabel = lastLockedBrowsers.join(", ");
  const runningBannerLabel = lastRunningBrowsers.join(", ");

  return (
    <div className="space-y-6">
      {lockedBannerVisible && pendingRetry ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-(--severity-high)/40 bg-(--severity-high)/12 px-4 py-3 text-sm text-(--foreground)">
          <span>
            {t("browserHistory.banner.locked").replace("{browsers}", lockedBannerLabel)}
          </span>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={browserDeleting}
              onClick={() => {
                const next: PendingBrowserDelete =
                  pendingRetry.mode === "all"
                    ? { kind: "all" }
                    : { kind: "ids", ids: [...pendingRetry.ids] };
                void runBrowserDeleteInner(next);
              }}
              className="rounded-lg border border-(--border) bg-(--surface) px-3 py-1.5 text-xs font-medium hover:bg-(--surface-2) disabled:opacity-50"
            >
              {t("browserHistory.banner.retry")}
            </button>
            <button
              type="button"
              onClick={() => {
                setLockedBannerVisible(false);
                setPendingRetry(null);
                setLastLockedBrowsers([]);
              }}
              className="rounded-lg border border-(--border) bg-transparent px-3 py-1.5 text-xs font-medium text-(--muted) hover:bg-(--surface-2)"
            >
              {t("browserHistory.banner.dismiss")}
            </button>
          </div>
        </div>
      ) : null}
      {runningBannerVisible && pendingRetry ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-(--severity-warn)/45 bg-(--severity-warn)/14 px-4 py-3 text-sm text-(--foreground)">
          <span>
            {t("browserHistory.banner.running").replace("{browsers}", runningBannerLabel)}
          </span>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={browserDeleting}
              onClick={() => {
                const next: PendingBrowserDelete =
                  pendingRetry.mode === "all"
                    ? { kind: "all" }
                    : { kind: "ids", ids: [...pendingRetry.ids] };
                void runBrowserDeleteInner(next);
              }}
              className="rounded-lg border border-(--border) bg-(--surface) px-3 py-1.5 text-xs font-medium hover:bg-(--surface-2) disabled:opacity-50"
            >
              {t("browserHistory.banner.retry")}
            </button>
            <button
              type="button"
              onClick={() => {
                setRunningBannerVisible(false);
                setLastRunningBrowsers([]);
              }}
              className="rounded-lg border border-(--border) bg-transparent px-3 py-1.5 text-xs font-medium text-(--muted) hover:bg-(--surface-2)"
            >
              {t("browserHistory.banner.dismiss")}
            </button>
          </div>
        </div>
      ) : null}

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("browserHistory.title")}
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-(--muted)">
            {t("browserHistory.subtitle")}
          </p>
          {selectedIds.size > 0 ? (
            <p className="mt-2 text-xs text-(--muted)">
              {t("browserHistory.selected").replace("{count}", String(selectedIds.size))}
            </p>
          ) : null}
          {lastScan ? (
            <p className="mt-2 text-xs text-(--muted)">
              {t("browserHistory.lastScanAt").replace(
                "{when}",
                formatRelativeTime(lastScan.scannedAt),
              )}
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={scanning}
            onClick={() => void runScan()}
            className="inline-flex items-center gap-2 rounded-lg border border-(--accent)/35 bg-(--accent)/15 px-3 py-2 text-xs font-medium text-(--foreground) transition-colors duration-200 hover:bg-(--accent)/25 disabled:opacity-50"
          >
            {scanning ? (
              <Loader2 className="size-3.5 animate-spin" aria-hidden />
            ) : null}
            {scanning ? t("browserHistory.scanning") : t("browserHistory.scanNow")}
          </button>
          <button
            type="button"
            disabled={selectedIds.size === 0 || browserDeleting}
            onClick={() => requestBrowserDelete({ kind: "ids", ids: [...selectedIds] })}
            className="inline-flex items-center gap-2 rounded-lg border border-(--accent)/40 bg-(--accent)/20 px-3 py-2 text-xs font-medium text-(--foreground) transition-colors duration-200 hover:bg-(--accent)/30 disabled:opacity-50"
          >
            <ShieldX className="size-3.5" aria-hidden />
            {t("browserHistory.action.removeSelected")}
          </button>
          <button
            type="button"
            disabled={rows.length === 0 || browserDeleting}
            onClick={() => requestBrowserDelete({ kind: "all" })}
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--surface-2) px-3 py-2 text-xs font-medium text-(--foreground) transition-colors duration-200 hover:bg-(--surface) disabled:opacity-50"
          >
            <ShieldX className="size-3.5 opacity-80" aria-hidden />
            {t("browserHistory.action.removeAll")}
          </button>
          <button
            type="button"
            onClick={() => setConfirmClear(true)}
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--surface)/80 px-3 py-2 text-xs font-medium text-(--muted) transition-colors duration-200 hover:bg-(--surface-2) hover:text-(--foreground)"
          >
            <Eraser className="size-3.5" aria-hidden />
            {t("browserHistory.action.clearLocalOnly")}
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-(--border) bg-(--surface)/80 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-(--muted)">
            {t("browserHistory.stats.urlsScanned")}
          </div>
          <div className="mt-1 text-2xl font-semibold tabular-nums text-(--foreground)">
            {lastScan?.urlsScanned ?? "—"}
          </div>
        </div>
        <SeverityDonut counts={donutCounts} centerValue={filtered.length} />
        <div className="rounded-xl border border-(--border) bg-(--surface)/80 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-(--muted)">
            {t("browserHistory.stats.browsersDetected")}
          </div>
          <div className="mt-1 text-sm text-(--foreground)">
            {lastScan?.browsersScanned?.length
              ? lastScan.browsersScanned.join(", ")
              : "—"}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-1.5">
          <span className="mr-2 self-center text-[10px] font-semibold uppercase tracking-wide text-(--muted)">
            Severity
          </span>
          {(["all", "high", "warn", "low"] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSev(s)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
                sev === s
                  ? "bg-(--accent)/25 text-(--foreground) ring-1 ring-(--accent)/40"
                  : "bg-(--surface-2) text-(--muted) hover:text-(--foreground)"
              }`}
            >
              {s === "all"
                ? t("activity.filters.all")
                : s === "high"
                  ? t("processes.filterHigh")
                  : s === "warn"
                    ? t("processes.filterWarn")
                    : t("logs.severity.low")}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className="mr-2 self-center text-[10px] font-semibold uppercase tracking-wide text-(--muted)">
            Category
          </span>
          {CAT_CHIPS.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setCat(c.id)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium transition-colors ${
                cat === c.id
                  ? "bg-(--accent)/25 text-(--foreground) ring-1 ring-(--accent)/40"
                  : "bg-(--surface-2) text-(--muted) hover:text-(--foreground)"
              }`}
            >
              {t(c.labelKey)}
            </button>
          ))}
        </div>
      </div>

      {!loading && filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-(--border) bg-(--surface)/40 px-6 py-16 text-center">
          <p className="text-sm font-medium text-(--foreground)">
            {t("browserHistory.empty.title")}
          </p>
          <p className="mt-2 text-sm text-(--muted)">
            {showAfterScrubEmpty ? t("browserHistory.empty.afterClear") : t("browserHistory.empty.body")}
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-(--border) bg-(--surface)/60">
          {!loading ? (
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-(--border) px-4 py-3 text-xs text-(--muted)">
              <span>
                {t("rules.pagination.showing")}{" "}
                {filtered.length === 0 ? 0 : safePage * PAGE_SIZE + 1}–
                {Math.min((safePage + 1) * PAGE_SIZE, filtered.length)}{" "}
                {t("rules.pagination.of")} {filtered.length}
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={safePage <= 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="rounded border border-(--border) px-2 py-1 transition-colors duration-200 hover:bg-(--surface-2) disabled:opacity-40"
                >
                  {t("rules.pagination.prev")}
                </button>
                <button
                  type="button"
                  disabled={safePage >= pageCount - 1}
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                  className="rounded border border-(--border) px-2 py-1 transition-colors duration-200 hover:bg-(--surface-2) disabled:opacity-40"
                >
                  {t("rules.pagination.next")}
                </button>
              </div>
            </div>
          ) : null}
          <StickyTable className={loading ? undefined : "sticky-table-wrap-flush"}>
          <table className="sticky-table min-w-[960px] text-left">
            <colgroup>
              <col style={{ width: 40 }} />
              <col style={{ width: 32 }} />
              <col style={{ width: 140 }} />
              <col style={{ minWidth: 120 }} />
              <col style={{ width: "18%" }} />
              <col style={{ width: "32%" }} />
              <col style={{ minWidth: 160 }} />
              <col style={{ minWidth: 88 }} />
              <col style={{ width: 72 }} />
              <col style={{ width: 56 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left px-2">
                  <input
                    ref={headerCheckboxRef}
                    type="checkbox"
                    checked={filtered.length > 0 && selectedOnPage.length === filtered.length}
                    onChange={() => toggleSelectAllFiltered()}
                    aria-label={t("browserHistory.selectAll")}
                    className="accent-(--accent)"
                  />
                </th>
                <th className="col-sticky-left-2 px-1 text-center" aria-hidden />
                <th className="col-sticky-left-3">
                  {t("browserHistory.columns.time")}
                </th>
                <th>{t("browserHistory.columns.browser")}</th>
                <th>{t("browserHistory.columns.host")}</th>
                <th>{t("browserHistory.columns.url")}</th>
                <th>{t("browserHistory.columns.categories")}</th>
                <th>{t("browserHistory.columns.severity")}</th>
                <th>{t("browserHistory.columns.score")}</th>
                <th className="col-sticky-right text-center"> </th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-(--muted)">
                    <Loader2 className="mx-auto size-6 animate-spin opacity-60" aria-hidden />
                  </td>
                </tr>
              ) : (
                slice.map((r) => {
                  const sevColor =
                    r.severity === "high"
                      ? "var(--severity-high)"
                      : r.severity === "warn"
                        ? "var(--severity-warn)"
                        : "var(--severity-low)";
                  const browserLine = `${r.browser}\u00A0·\u00A0${r.profile}`;
                  return (
                    <tr key={String(r.id)} className="align-top">
                      <td className="col-sticky-left px-2">
                        <input
                          type="checkbox"
                          checked={selectedIds.has(r.id)}
                          onChange={() => toggleRowSelected(r.id)}
                          aria-label={`${r.browser} · ${r.host}`}
                          className="accent-(--accent)"
                        />
                      </td>
                      <td className="col-sticky-left-2 text-center align-middle">
                        <span
                          className="inline-block size-2 rounded-full"
                          style={{ background: sevColor }}
                          title={t(severityLabelKey(r.severity))}
                        />
                      </td>
                      <td className="col-sticky-left-3 whitespace-nowrap text-(--muted)">
                        {timeFmt.format(new Date(r.lastVisitAt))}
                      </td>
                      <td className="max-w-0 text-(--foreground)" title={browserLine}>
                        <span className="block truncate text-sm">{browserLine}</span>
                      </td>
                      <TruncCell value={r.host} />
                      <td className="max-w-0 font-mono text-xs">
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="min-w-0 flex-1 truncate" title={r.url}>
                            {r.url}
                          </span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              void copyUrl(r.url);
                            }}
                            className="inline-flex shrink-0 items-center gap-1 text-[10px] text-(--accent) hover:underline"
                          >
                            <Copy className="size-3" aria-hidden />
                            <span className="sr-only">{t("browserHistory.copyUrl")}</span>
                          </button>
                        </div>
                      </td>
                      <td>
                        <div className="flex max-w-[320px] flex-wrap gap-1">
                          {r.matchedCategories.map((c) => {
                            const ck = categoryBadgeLabelKey(c);
                            return (
                              <span key={c} className={categoryChipClass(c)}>
                                {ck ? t(ck) : c}
                              </span>
                            );
                          })}
                        </div>
                      </td>
                      <td>
                        <span
                          className={`inline-flex rounded-md px-2 py-0.5 text-xs font-medium capitalize ${severityBadgeClass(r.severity)}`}
                        >
                          {t(severityLabelKey(r.severity))}
                        </span>
                      </td>
                      <td className="tabular-nums text-(--foreground)">{r.score}</td>
                      <td className="col-sticky-right text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          title={t("browserHistory.action.removeRow")}
                          disabled={browserDeleting}
                          onClick={(e) => {
                            e.stopPropagation();
                            requestBrowserDelete({ kind: "ids", ids: [r.id] });
                          }}
                          className="inline-flex rounded-md border border-(--border) p-1.5 text-(--muted) transition-colors hover:border-(--severity-high)/40 hover:bg-(--severity-high)/10 hover:text-(--severity-high) disabled:opacity-50"
                        >
                          <Trash2 className="size-3.5" aria-hidden />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </StickyTable>
        </div>
      )}

      {confirmClear ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="max-w-md rounded-xl border border-(--border) bg-(--background) p-6 shadow-xl">
            <h2 className="text-lg font-semibold text-(--foreground)">
              {t("browserHistory.clearConfirmTitle")}
            </h2>
            <p className="mt-2 text-sm text-(--muted)">
              {t("browserHistory.clearConfirmBody")}
            </p>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmClear(false)}
                className="rounded-lg border border-(--border) px-3 py-2 text-sm"
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                onClick={() => void confirmClearRun()}
                className="rounded-lg bg-(--severity-high) px-3 py-2 text-sm font-medium text-white"
              >
                {t("common.confirm")}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {deleteFlow.stage !== "idle" ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="max-w-md rounded-xl border border-(--border) bg-(--background) p-6 shadow-xl">
            {deleteFlow.stage === "confirm" ? (
              <>
                <h2 className="text-lg font-semibold text-(--foreground)">
                  {t("browserHistory.confirm.title")}
                </h2>
                <p className="mt-2 text-sm text-(--muted)">
                  {t("browserHistory.confirm.body")
                    .replace("{count}", String(pendingModalCount))
                    .replace("{browsers}", pendingModalBrowsers || "—")}
                </p>
                <label className="mt-4 flex cursor-pointer items-center gap-2 text-sm text-(--foreground)">
                  <input
                    type="checkbox"
                    checked={dontAskAgainBrowserDelete}
                    onChange={(e) => setDontAskAgainBrowserDelete(e.target.checked)}
                    className="accent-(--accent)"
                  />
                  {t("browserHistory.confirm.dontAskAgain")}
                </label>
                <div className="mt-6 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setDeleteFlow({ stage: "idle" })}
                    className="rounded-lg border border-(--border) px-3 py-2 text-sm"
                  >
                    {t("browserHistory.confirm.cancel")}
                  </button>
                  <button
                    type="button"
                    disabled={browserDeleting}
                    onClick={() => void confirmBrowserDeleteRun()}
                    className="rounded-lg bg-(--severity-high) px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
                  >
                    {t("browserHistory.confirm.confirm")}
                  </button>
                </div>
              </>
            ) : deleteFlow.stage === "browser-running" ? (
              <>
                <h2 className="text-lg font-semibold text-(--foreground)">
                  {t("browserHistory.running.title").replace("{browser}", deleteFlow.browser)}
                </h2>
                <p className="mt-2 text-sm text-(--muted)">
                  {t("browserHistory.running.body").replace(/\{browser\}/g, deleteFlow.browser)}
                </p>
                <div className="mt-6 flex flex-wrap justify-end gap-2">
                  <button
                    type="button"
                    disabled={browserDeleting}
                    onClick={() => setDeleteFlow({ stage: "idle" })}
                    className="rounded-lg border border-(--border) bg-transparent px-3 py-2 text-sm text-(--muted) hover:bg-(--surface-2) disabled:opacity-50"
                  >
                    {t("browserHistory.running.cancel")}
                  </button>
                  <button
                    type="button"
                    disabled={browserDeleting}
                    onClick={() =>
                      void attemptCloseBrowser(deleteFlow.pending, deleteFlow.browser, true)
                    }
                    className="rounded-lg border border-(--severity-high)/45 bg-(--severity-high)/12 px-3 py-2 text-sm font-medium text-(--severity-high) hover:bg-(--severity-high)/18 disabled:opacity-50"
                  >
                    {t("browserHistory.running.forceClose")}
                  </button>
                  <button
                    type="button"
                    disabled={browserDeleting}
                    onClick={() =>
                      void attemptCloseBrowser(deleteFlow.pending, deleteFlow.browser, false)
                    }
                    className="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--foreground) hover:bg-(--accent)/90 disabled:opacity-50"
                  >
                    {t("browserHistory.running.close").replace("{browser}", deleteFlow.browser)}
                  </button>
                </div>
              </>
            ) : deleteFlow.stage === "closing" ? (
              <div className="flex flex-col items-center gap-4 py-2">
                <Loader2 className="size-8 animate-spin text-(--accent)" aria-hidden />
                <p className="text-center text-sm font-medium text-(--foreground)">
                  {t("browserHistory.closing.title").replace("{browser}", deleteFlow.browser)}
                </p>
                <button
                  type="button"
                  disabled={browserDeleting}
                  onClick={() => setDeleteFlow({ stage: "idle" })}
                  className="rounded-lg border border-(--border) px-3 py-2 text-xs text-(--muted) hover:bg-(--surface-2) disabled:opacity-50"
                >
                  {t("browserHistory.running.cancel")}
                </button>
              </div>
            ) : deleteFlow.stage === "unresponsive" ? (
              <>
                <h2 className="text-lg font-semibold text-(--foreground)">
                  {t("browserHistory.unresponsive.title").replace("{browser}", deleteFlow.browser)}
                </h2>
                <p className="mt-2 text-sm text-(--muted)">
                  {t("browserHistory.unresponsive.body")}
                </p>
                <div className="mt-6 flex justify-end gap-2">
                  <button
                    type="button"
                    disabled={browserDeleting}
                    onClick={() => setDeleteFlow({ stage: "idle" })}
                    className="rounded-lg border border-(--border) px-3 py-2 text-sm disabled:opacity-50"
                  >
                    {t("browserHistory.running.cancel")}
                  </button>
                  <button
                    type="button"
                    disabled={browserDeleting}
                    onClick={() =>
                      void attemptCloseBrowser(deleteFlow.pending, deleteFlow.browser, true)
                    }
                    className="rounded-lg border border-(--severity-high)/45 bg-(--severity-high)/15 px-3 py-2 text-sm font-medium text-(--severity-high) hover:bg-(--severity-high)/22 disabled:opacity-50"
                  >
                    {t("browserHistory.unresponsive.forceClose")}
                  </button>
                </div>
              </>
            ) : (
              <div className="flex flex-col items-center gap-4 py-4">
                <Loader2 className="size-8 animate-spin text-(--accent)" aria-hidden />
                <p className="text-center text-sm font-medium text-(--foreground)">
                  {t("browserHistory.deleting.title")}
                </p>
              </div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
