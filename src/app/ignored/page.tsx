"use client";

import { invoke } from "@tauri-apps/api/core";
import { Eye, EyeOff } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, useDeferredValue } from "react";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { useToast } from "@/components/Toast";
import { formatRelativeTime } from "@/lib/formatRelativeTime";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type { AllowlistEntry } from "@/lib/types";

export default function IgnoredPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [entries, setEntries] = useState<AllowlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [navPrimed, setNavPrimed] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await invoke<AllowlistEntry[]>("list_allowlist");
      if (!mountedRef.current) return;
      setEntries(list);
    } catch (e) {
      console.error("[ignored] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      if (!mountedRef.current) return;
      setLoading(false);
      setNavPrimed(true);
    }
  }, [showToast]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      setLoading(true);
      try {
        const list = await invoke<AllowlistEntry[]>("list_allowlist");
        if (cancelled) return;
        setEntries(list);
      } catch (e) {
        console.error("[ignored] ipc failed", e);
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
    if (!q) return entries;
    return entries.filter(
      (e) =>
        e.name.toLowerCase().includes(q) ||
        e.imagePath.toLowerCase().includes(q) ||
        (e.reason?.toLowerCase().includes(q) ?? false),
    );
  }, [entries, deferredSearch]);

  const unignore = async (imagePath: string) => {
    try {
      await invoke("remove_allowlist_entry", { imagePath });
      if (!mountedRef.current) return;
      showToast(t("allowlist.removedToast"), "info");
      await load();
    } catch (e) {
      console.error("[ignored] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-2">
          <EyeOff className="size-6 text-(--accent)" aria-hidden />
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("ignored.title")}
          </h1>
        </div>
        <p className="mt-2 max-w-2xl text-sm text-(--muted)">
          {t("ignored.subtitle")}
        </p>
      </div>

      <input
        type="search"
        placeholder={t("ignored.search")}
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="w-full max-w-md rounded-lg border border-(--border) bg-(--surface)/80 px-3 py-2 text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
      />

      <div className="min-w-0 overflow-hidden rounded-xl border border-(--border) bg-(--surface)/40">
        <StickyTable className="sticky-table-wrap-flush">
          <table className="sticky-table min-w-[720px] text-left">
            <colgroup>
              <col style={{ width: 200 }} />
              <col />
              <col style={{ width: 120 }} />
              <col style={{ width: "28%" }} />
              <col style={{ width: 72 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left">{t("ignored.columns.name")}</th>
                <th>{t("ignored.columns.path")}</th>
                <th>{t("ignored.columns.addedAt")}</th>
                <th>{t("ignored.columns.reason")}</th>
                <th className="col-sticky-right text-right">{t("startup.cols.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 5 }).map((_, i) => (
                    <tr key={`sk-${i}`}>
                      <td colSpan={5} className="py-3">
                        <Skeleton className="h-8 w-full" />
                      </td>
                    </tr>
                  ))
                : filtered.map((row) => (
                    <tr key={row.imagePath}>
                      <td className="col-sticky-left font-medium" title={row.name}>
                        {row.name}
                      </td>
                      <TruncCell value={row.imagePath} className="font-mono text-xs text-(--muted)" />
                      <td className="whitespace-nowrap text-(--muted)">
                        {formatRelativeTime(row.createdAt)}
                      </td>
                      <TruncCell value={row.reason ?? ""} className="text-(--muted)" />
                      <td className="col-sticky-right text-right">
                        <div className="flex items-center justify-end whitespace-nowrap">
                          <button
                            type="button"
                            title={t("ignored.unignore")}
                            aria-label={t("ignored.unignore")}
                            onClick={(e) => {
                              e.stopPropagation();
                              void unignore(row.imagePath);
                            }}
                            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-(--border) text-(--muted) transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2) hover:text-(--foreground)"
                          >
                            <Eye className="size-3.5" aria-hidden />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </StickyTable>
        {!loading && entries.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-6 py-14 text-center">
            <EyeOff className="size-10 text-(--muted)" aria-hidden />
            <div className="text-sm font-medium text-(--foreground)">
              {t("ignored.empty.title")}
            </div>
            <p className="max-w-sm text-sm text-(--muted)">
              {t("ignored.empty.body")}
            </p>
          </div>
        ) : null}
        {!loading && entries.length > 0 && filtered.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-(--muted)">
            {t("rules.noMatches")}
          </div>
        ) : null}
      </div>
    </div>
  );
}
