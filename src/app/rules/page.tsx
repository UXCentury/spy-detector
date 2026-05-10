"use client";

import { invoke } from "@tauri-apps/api/core";
import { motion } from "framer-motion";
import { ShieldQuestion } from "lucide-react";
import {
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { IocCatalogBanner } from "@/components/IocCatalogBanner";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { Toggle } from "@/components/Toggle";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";

type IocEntryView = {
  token: string;
  kind: string;
  source: string;
  disabled: boolean;
  indicatorCount?: number | null;
};

const PAGE_SIZE = 100;

export default function RulesPage() {
  const { t } = useLang();
  const { showToast } = useToast();

  const kindLabel = (kind: string) => {
    switch (kind) {
      case "process_name":
        return t("rules.kindProcessName");
      case "path_needle":
        return t("rules.kindPath");
      case "domain":
        return t("rules.kindDomain");
      case "ip":
        return t("rules.kindIp");
      case "ip_feed":
        return t("rules.kindIpFeed");
      default:
        return kind;
    }
  };

  const sourceLabel = (source: string) => {
    const s = source.toLowerCase();
    if (s.includes("bundled")) return t("rules.sourceBundled");
    if (s.includes("upstream")) return t("rules.sourceUpstream");
    if (s.includes("windows")) return t("rules.sourceWindows");
    return source;
  };
  const [entries, setEntries] = useState<IocEntryView[]>([]);
  const [search, setSearch] = useState("");
  const [kindOn, setKindOn] = useState<Record<string, boolean>>({
    process_name: true,
    path_needle: true,
    domain: true,
    ip: true,
    ip_feed: true,
  });
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [navPrimed, setNavPrimed] = useState(false);
  const deferredSearch = useDeferredValue(search);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      setLoading(true);
      try {
        const rows = await invoke<IocEntryView[]>("list_ioc_entries");
        if (cancelled) return;
        setEntries(rows);
      } catch (e) {
        console.error("[rules] ipc failed", e);
        if (cancelled) return;
        showToast(e instanceof Error ? e.message : String(e), "error");
      } finally {
        if (!cancelled) {
          setLoading(false);
          setNavPrimed(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [showToast]);

  usePageReady(navPrimed);

  const filtered = useMemo(() => {
    const q = deferredSearch.trim().toLowerCase();
    return entries.filter((row) => {
      if (!kindOn[row.kind]) return false;
      if (!q) return true;
      return row.token.toLowerCase().includes(q);
    });
  }, [entries, deferredSearch, kindOn]);

  const filterEpoch = useMemo(
    () => ({ deferredSearch, kindOn }),
    [deferredSearch, kindOn],
  );
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

  const toggleKind = (kind: string) => {
    setKindOn((prev) => ({ ...prev, [kind]: !prev[kind] }));
  };

  const toggleDisabled = async (row: IocEntryView, next: boolean) => {
    try {
      if (row.kind === "ip_feed") {
        await invoke("set_ip_feed_enabled", {
          slug: row.token,
          enabled: !next,
        });
      } else {
        await invoke("set_signature_disabled", {
          token: row.token,
          kind: row.kind,
          disabled: next,
        });
      }
      if (!mountedRef.current) return;
      setEntries((prev) =>
        prev.map((r) =>
          r.token === row.token && r.kind === row.kind
            ? { ...r, disabled: next }
            : r,
        ),
      );
    } catch (e) {
      console.error("[rules] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-8">
      <div>
        <div className="flex items-center gap-2">
          <ShieldQuestion className="size-6 text-(--accent)" aria-hidden />
          <h1 className="text-2xl font-semibold tracking-tight">{t("rules.title")}</h1>
        </div>
        <p className="mt-2 text-sm text-(--muted)">
          {(() => {
            const sub = t("rules.subtitle");
            const parts = sub.split("net:");
            return parts.length >= 2 ? (
              <>
                {parts[0]}
                <span className="font-mono text-xs">net:</span>
                {parts.slice(1).join("net:")}
              </>
            ) : (
              sub
            );
          })()}
        </p>
      </div>

      <IocCatalogBanner />

      <div className="flex flex-col gap-4 rounded-xl border border-(--border) bg-(--surface)/70 p-6 backdrop-blur-md">
        <label className="block text-sm">
          <span className="text-(--muted)">{t("rules.search")}</span>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("rules.searchPlaceholder")}
            className="mt-1 w-full rounded-lg border border-(--border) bg-(--background)/80 px-3 py-2 font-mono text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
          />
        </label>

        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-(--muted)">
            {t("rules.kindHeading")}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {(
              [
                ["process_name", "rules.filterProcessName"],
                ["path_needle", "rules.filterPath"],
                ["domain", "rules.filterDomain"],
                ["ip", "rules.filterIp"],
                ["ip_feed", "rules.filterIpFeed"],
              ] as const
            ).map(([kind, key]) => (
              <motion.button
                key={kind}
                type="button"
                whileTap={{ scale: 0.97 }}
                onClick={() => toggleKind(kind)}
                className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-200 ${
                  kindOn[kind]
                    ? "border-(--accent) bg-(--accent)/20 text-(--foreground)"
                    : "border-(--border) text-(--muted) hover:bg-(--surface-2)"
                }`}
              >
                {t(key)}
              </motion.button>
            ))}
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-(--border) bg-(--surface)/60">
        <div className="flex items-center justify-between border-b border-(--border) px-4 py-3 text-xs text-(--muted)">
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

        <StickyTable className="sticky-table-wrap-flush">
          <table className="sticky-table min-w-[640px] text-left">
            <colgroup>
              <col style={{ width: 240 }} />
              <col style={{ minWidth: 120 }} />
              <col style={{ width: "40%" }} />
              <col style={{ width: 96 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left">{t("rules.colToken")}</th>
                <th>{t("rules.colKind")}</th>
                <th>{t("rules.colSource")}</th>
                <th className="col-sticky-right">{t("rules.colEnabled")}</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 8 }).map((_, i) => (
                    <tr key={`sk-${i}`}>
                      <td colSpan={4} className="py-2">
                        <Skeleton className="h-8 w-full" />
                      </td>
                    </tr>
                  ))
                : slice.map((row) => (
                    <tr key={`${row.kind}:${row.token}`}>
                      <td className="col-sticky-left font-mono text-xs">
                        <div className="truncate" title={row.token}>
                          {row.token}
                        </div>
                        {row.indicatorCount != null ? (
                          <div className="mt-0.5 text-[10px] font-normal text-(--muted)">
                            {t("ipFeeds.indicators").replace(
                              "{count}",
                              String(row.indicatorCount),
                            )}
                          </div>
                        ) : null}
                      </td>
                      <td className="text-(--muted)">{kindLabel(row.kind)}</td>
                      <TruncCell value={sourceLabel(row.source)} className="text-(--muted)" />
                      <td className="col-sticky-right align-middle">
                        <div className="flex items-center justify-end whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <Toggle
                            checked={!row.disabled}
                            onChange={(next) => void toggleDisabled(row, !next)}
                            ariaLabel={`Enable rule ${row.kind} ${row.token}`}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </StickyTable>

        {!loading && filtered.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-(--muted)">
            {t("rules.noMatches")}
          </div>
        ) : null}
      </div>
    </div>
  );
}
