"use client";

import { invoke } from "@tauri-apps/api/core";
import { ChevronDown, ChevronRight, RefreshCw, Trash2 } from "lucide-react";
import {
  Fragment,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { usePageReady } from "@/lib/PageStatus";
import { useTauriEvent } from "@/lib/hooks/useTauriEvent";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import type { EventLogRow } from "@/lib/types";
import { useToast } from "@/components/Toast";

const PAGE = 100;
/** Cap appended rows in React state (ORDER BY id DESC + offset loads older rows). */
const MAX_BUFFERED_ROWS = 500;

const SEVERITIES_DEFAULT = new Set(["info", "low", "warn", "high"]);

type ChipId =
  | "all"
  | "camera"
  | "microphone"
  | "hooks"
  | "clipboard"
  | "process"
  | "thread"
  | "scan"
  | "findings"
  | "actions"
  | "allowlist"
  | "ioc"
  | "autostart"
  | "settings"
  | "app";

const CHIP_KINDS: Record<Exclude<ChipId, "all">, string[]> = {
  camera: ["camera-access"],
  microphone: ["microphone-access"],
  hooks: ["keyboard-hook"],
  clipboard: ["clipboard-access"],
  process: ["process-launch", "process-exit"],
  thread: ["thread-injection", "thread-burst"],
  scan: ["scan-started", "scan-completed"],
  findings: ["finding-new"],
  actions: ["alert-emitted", "process-killed", "process-quarantined"],
  allowlist: ["ignored", "unignored"],
  ioc: ["ioc-refresh", "ip-feed-match"],
  autostart: ["autostart-added", "autostart-removed"],
  settings: ["settings-changed"],
  app: [
    "app-started",
    "app-stopped",
    "elevation-requested",
    "etw-subscription-state-changed",
  ],
};

const CHIPS: { id: ChipId; labelKey: StringKey }[] = [
  { id: "all", labelKey: "logs.filters.all" },
  { id: "camera", labelKey: "logs.kinds.camera" },
  { id: "microphone", labelKey: "logs.kinds.microphone" },
  { id: "hooks", labelKey: "logs.kinds.hooks" },
  { id: "clipboard", labelKey: "logs.kinds.clipboard" },
  { id: "process", labelKey: "logs.kinds.process" },
  { id: "thread", labelKey: "logs.kinds.thread" },
  { id: "scan", labelKey: "logs.kinds.scan" },
  { id: "findings", labelKey: "logs.kinds.findings" },
  { id: "actions", labelKey: "logs.kinds.actions" },
  { id: "allowlist", labelKey: "logs.kinds.allowlist" },
  { id: "ioc", labelKey: "logs.kinds.ioc" },
  { id: "autostart", labelKey: "logs.kinds.autostart" },
  { id: "settings", labelKey: "logs.kinds.settings" },
  { id: "app", labelKey: "logs.kinds.app" },
];

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

function formatKindLabel(kind: string): string {
  return kind.replace(/-/g, " ");
}

function severityLabelKey(sev: string): StringKey {
  if (sev === "info") return "logs.severity.info";
  if (sev === "low") return "logs.severity.low";
  if (sev === "warn") return "logs.severity.warn";
  if (sev === "high") return "logs.severity.high";
  return "logs.severity.info";
}

export default function LogsPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [bootReady, setBootReady] = useState(false);
  const [rows, setRows] = useState<EventLogRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [chip, setChip] = useState<ChipId>("all");
  const [enabledSev, setEnabledSev] = useState(() =>
    new Set<string>(["info", "low", "warn", "high"]),
  );
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [clearTotal, setClearTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [pillCount, setPillCount] = useState(0);
  const pendingNewRef = useRef(0);
  const pillTimerRef = useRef<number | null>(null);
  const pagePrimed = useRef(false);
  const mountedRef = useRef(true);
  const fetchReqIdRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const queryKinds = useMemo(() => {
    if (chip === "all") return null;
    return CHIP_KINDS[chip];
  }, [chip]);

  const querySeverities = useMemo(() => {
    if (enabledSev.size === 4) return null;
    return [...enabledSev];
  }, [enabledSev]);

  const fetchSlice = useCallback(
    async (offset: number, append: boolean) => {
      const reqId = ++fetchReqIdRef.current;
      setLoading(true);
      try {
        const q = deferredSearch.trim() || null;
        const list = await invoke<EventLogRow[]>("list_event_log", {
          limit: PAGE,
          offset,
          kinds: queryKinds,
          search: q,
          severities: querySeverities,
        });
        if (!mountedRef.current || reqId !== fetchReqIdRef.current) return;
        const count = await invoke<number>("count_event_log", {
          kinds: queryKinds,
          search: q,
          severities: querySeverities,
        });
        if (!mountedRef.current || reqId !== fetchReqIdRef.current) return;
        setTotal(count);
        const mergedLogicalLen = append ? offset + list.length : list.length;
        const hitBufferCap = mergedLogicalLen > MAX_BUFFERED_ROWS;
        setRows((prev) => {
          const next = append ? [...prev, ...list] : list;
          return next.length > MAX_BUFFERED_ROWS ? next.slice(0, MAX_BUFFERED_ROWS) : next;
        });
        setHasMore(
          list.length === PAGE &&
            offset + list.length < count &&
            !hitBufferCap,
        );
      } catch (e) {
        console.error("[logs] ipc failed", e);
      } finally {
        if (mountedRef.current && reqId === fetchReqIdRef.current) {
          setLoading(false);
        }
      }
    },
    [deferredSearch, queryKinds, querySeverities],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      await fetchSlice(0, false);
      if (!cancelled && !pagePrimed.current) {
        pagePrimed.current = true;
        setBootReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fetchSlice]);

  usePageReady(bootReady);

  useTauriEvent<{ id: number }>("event_logged", () => {
    pendingNewRef.current += 1;
    if (pillTimerRef.current) window.clearTimeout(pillTimerRef.current);
    pillTimerRef.current = window.setTimeout(() => {
      setPillCount(pendingNewRef.current);
      pillTimerRef.current = null;
    }, 1000);
  });

  const refresh = useCallback(() => {
    pendingNewRef.current = 0;
    setPillCount(0);
    void fetchSlice(0, false);
  }, [fetchSlice]);

  const loadMore = () => {
    void fetchSlice(rows.length, true);
  };

  const openClearConfirm = async () => {
    try {
      const n = await invoke<number>("count_event_log", {
        kinds: null,
        search: null,
        severities: null,
      });
      if (!mountedRef.current) return;
      setClearTotal(n);
      setConfirmOpen(true);
    } catch (e) {
      console.error("[logs] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const confirmClear = async () => {
    try {
      await invoke("clear_event_log");
      if (!mountedRef.current) return;
      setConfirmOpen(false);
      showToast(t("logs.cleared"), "info");
      refresh();
    } catch (e) {
      console.error("[logs] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const toggleSeverity = (s: string) => {
    setEnabledSev((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      if (next.size === 0) return new Set(SEVERITIES_DEFAULT);
      return next;
    });
  };

  const timeFmt = useMemo(
    () =>
      new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }),
    [],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("logs.title")}
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-(--muted)">
            {t("logs.subtitle")}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--surface)/80 px-3 py-2 text-xs font-medium transition-colors duration-200 hover:bg-(--surface-2)"
          >
            <RefreshCw className="size-3.5" aria-hidden />
            {t("logs.refresh")}
          </button>
          <button
            type="button"
            onClick={() => void openClearConfirm()}
            className="inline-flex items-center gap-2 rounded-lg border border-(--severity-high)/35 bg-(--severity-high)/10 px-3 py-2 text-xs font-medium text-(--severity-high) transition-colors duration-200 hover:bg-(--severity-high)/20"
          >
            <Trash2 className="size-3.5" aria-hidden />
            {t("logs.clear")}
          </button>
        </div>
      </div>

      {pillCount > 0 ? (
        <button
          type="button"
          onClick={refresh}
          className="w-full rounded-lg border border-(--accent)/30 bg-(--accent)/10 px-3 py-2 text-left text-sm text-(--foreground) transition-colors hover:bg-(--accent)/15"
        >
          {t("logs.newEntries").replace("{count}", String(pillCount))}
        </button>
      ) : null}

      <div className="flex flex-col gap-3">
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t("logs.search")}
          className="w-full max-w-md rounded-lg border border-(--border) bg-(--surface) px-3 py-2 text-sm outline-none ring-(--accent)/40 focus:ring-2"
        />
        <div className="flex flex-wrap gap-1.5">
          {CHIPS.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setChip(c.id)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium transition-colors ${
                chip === c.id
                  ? "bg-(--accent)/25 text-(--foreground) ring-1 ring-(--accent)/40"
                  : "bg-(--surface-2) text-(--muted) hover:text-(--foreground)"
              }`}
            >
              {t(c.labelKey)}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {(["info", "low", "warn", "high"] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => toggleSeverity(s)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
                enabledSev.has(s)
                  ? `${severityBadgeClass(s)}`
                  : "bg-(--surface-2) text-(--muted) line-through opacity-60"
              }`}
            >
              {t(severityLabelKey(s))}
            </button>
          ))}
        </div>
      </div>

      <p className="text-sm text-(--muted)">
        {t("logs.totals")
          .replace("{shown}", String(rows.length))
          .replace("{total}", String(total))}
      </p>

      {rows.length === 0 && !loading ? (
        <div className="rounded-xl border border-dashed border-(--border) bg-(--surface)/50 px-6 py-14 text-center">
          <p className="text-sm font-medium text-(--foreground)">
            {t("logs.empty.title")}
          </p>
          <p className="mt-2 text-sm text-(--muted)">{t("logs.empty.body")}</p>
        </div>
      ) : (
        <StickyTable>
          <table
            className="sticky-table min-w-[720px] text-left"
            style={{ tableLayout: "fixed" }}
          >
            <colgroup>
              <col style={{ width: 40 }} />
              <col style={{ width: 160 }} />
              <col style={{ width: 220 }} />
              <col style={{ width: 96 }} />
              <col style={{ width: "22%" }} />
              <col />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left" aria-hidden />
                <th className="col-sticky-left-2" style={{ left: 40 }}>
                  {t("logs.columns.time")}
                </th>
                <th className="col-sticky-left-3" style={{ left: 200 }}>
                  {t("logs.columns.kind")}
                </th>
                <th>{t("logs.columns.severity")}</th>
                <th>{t("logs.columns.process")}</th>
                <th>{t("logs.columns.summary")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <LogsTableRow key={row.id} row={row} timeFmt={timeFmt} t={t} />
              ))}
            </tbody>
          </table>
        </StickyTable>
      )}

      {hasMore ? (
        <button
          type="button"
          disabled={loading}
          onClick={loadMore}
          className="rounded-lg border border-(--border) bg-(--surface)/80 px-4 py-2 text-sm font-medium text-(--foreground) transition-colors hover:bg-(--surface-2) disabled:opacity-50"
        >
          {t("logs.loadMore")}
        </button>
      ) : null}

      {confirmOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="max-w-md rounded-xl border border-(--border) bg-(--surface) p-6 shadow-lg">
            <h2 className="text-lg font-semibold">{t("logs.confirmClearTitle")}</h2>
            <p className="mt-2 text-sm text-(--muted)">
              {t("logs.confirmClearBody").replace("{count}", String(clearTotal))}
            </p>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmOpen(false)}
                className="rounded-lg border border-(--border) px-3 py-2 text-sm"
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                onClick={() => void confirmClear()}
                className="rounded-lg bg-(--severity-high) px-3 py-2 text-sm font-medium text-white"
              >
                {t("common.confirm")}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function LogsTableRow({
  row,
  timeFmt,
  t,
}: {
  row: EventLogRow;
  timeFmt: Intl.DateTimeFormat;
  t: (k: StringKey) => string;
}) {
  const [open, setOpen] = useState(false);
  const detailsPretty = useMemo(
    () => (open ? JSON.stringify(row.details, null, 2) : ""),
    [open, row.details],
  );
  const hasDetails =
    row.details != null && Object.keys(row.details).length > 0;
  const proc =
    row.processName != null && row.processName !== ""
      ? row.processName
      : "—";
  const pidBit =
    row.pid != null && row.pid !== undefined ? ` (PID ${row.pid})` : "";

  return (
    <Fragment>
      <tr className="align-top">
        <td className="col-sticky-left">
          {hasDetails ? (
            <button
              type="button"
              className="text-(--muted) hover:text-(--foreground)"
              aria-expanded={open}
              onClick={() => setOpen((o) => !o)}
            >
              {open ? (
                <ChevronDown className="size-4" aria-hidden />
              ) : (
                <ChevronRight className="size-4" aria-hidden />
              )}
            </button>
          ) : null}
        </td>
        <td className="col-sticky-left-2 whitespace-nowrap text-(--muted)" style={{ left: 40 }}>
          {timeFmt.format(new Date(row.ts))}
        </td>
        <td className="col-sticky-left-3" style={{ left: 200 }}>
          <span
            className={`inline-flex whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium capitalize ${severityBadgeClass(row.severity)}`}
          >
            {formatKindLabel(row.kind)}
          </span>
        </td>
        <td className="whitespace-nowrap capitalize text-(--foreground)">
          {t(severityLabelKey(row.severity))}
        </td>
        <TruncCell value={`${proc}${pidBit}`} className="text-(--foreground)" />
        <TruncCell value={row.summary} className="text-(--foreground)" />
      </tr>
      {open && hasDetails ? (
        <tr className="border-b border-(--border)/80 bg-(--surface-2)/50">
          <td colSpan={6} className="px-3 py-3">
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-(--border) bg-(--background) p-3 font-mono text-xs text-(--foreground)">
              {detailsPretty}
            </pre>
          </td>
        </tr>
      ) : null}
    </Fragment>
  );
}
