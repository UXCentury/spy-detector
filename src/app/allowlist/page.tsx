"use client";

import { invoke } from "@tauri-apps/api/core";
import { ListPlus, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type { AllowlistEntry } from "@/lib/types";

export default function AllowlistPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [entries, setEntries] = useState<AllowlistEntry[]>([]);
  const [pathInput, setPathInput] = useState("");
  const [loading, setLoading] = useState(true);
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
      console.error("[allowlist] ipc failed", e);
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
        console.error("[allowlist] ipc failed", e);
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

  const trustPath = async () => {
    const p = pathInput.trim();
    if (!p) return;
    try {
      await invoke("set_allowlist_trusted", { path: p, trusted: true });
      if (!mountedRef.current) return;
      setPathInput("");
      await load();
      if (!mountedRef.current) return;
      showToast(t("allowlist.trustedToast"), "success");
    } catch (e) {
      console.error("[allowlist] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const untrust = async (p: string) => {
    try {
      await invoke("set_allowlist_trusted", { path: p, trusted: false });
      await load();
      if (!mountedRef.current) return;
      showToast(t("allowlist.removedToast"), "info");
    } catch (e) {
      console.error("[allowlist] ipc failed", e);
      if (!mountedRef.current) return;
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-8">
      <div>
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-6 text-(--accent)" aria-hidden />
          <h1 className="text-2xl font-semibold tracking-tight">{t("allowlist.title")}</h1>
        </div>
        <p className="mt-2 text-sm text-(--muted)">{t("allowlist.subtitle")}</p>
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          type="text"
          placeholder={t("allowlist.placeholder")}
          className="min-w-[240px] flex-1 rounded-lg border border-(--border) bg-(--surface)/80 px-3 py-2 font-mono text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
        />
        <button
          type="button"
          onClick={() => void trustPath()}
          className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90"
        >
          <ListPlus className="size-4" aria-hidden />
          {t("allowlist.add")}
        </button>
      </div>

      <div className="overflow-hidden rounded-xl border border-(--border) bg-(--surface)/60">
        <StickyTable className="sticky-table-wrap-flush">
          <table className="sticky-table min-w-[560px] text-left">
            <colgroup>
              <col style={{ width: 200 }} />
              <col />
              <col style={{ width: "35%" }} />
              <col style={{ width: 72 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left">{t("ignored.columns.name")}</th>
                <th>{t("ignored.columns.path")}</th>
                <th>{t("ignored.columns.reason")}</th>
                <th className="col-sticky-right text-right">{t("startup.cols.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 4 }).map((_, i) => (
                    <tr key={`sk-${i}`}>
                      <td colSpan={4} className="py-3">
                        <Skeleton className="h-5 w-full" />
                      </td>
                    </tr>
                  ))
                : entries.map((row) => (
                    <tr key={row.imagePath}>
                      <td className="col-sticky-left font-medium text-(--foreground)">
                        {row.name}
                      </td>
                      <TruncCell value={row.imagePath} className="font-mono text-xs text-(--muted)" />
                      <TruncCell value={row.reason ?? ""} className="text-(--muted)" />
                      <td className="col-sticky-right text-right">
                        <div className="flex items-center justify-end whitespace-nowrap">
                          <button
                            type="button"
                            title={t("allowlist.removeButton")}
                            aria-label={t("allowlist.removeButton")}
                            onClick={(e) => {
                              e.stopPropagation();
                              void untrust(row.imagePath);
                            }}
                            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-(--border) text-(--muted) transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2) hover:text-(--foreground)"
                          >
                            <X className="size-3.5" aria-hidden />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </StickyTable>
        {!loading && entries.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-(--muted)">
            {t("allowlist.empty")}
          </div>
        ) : null}
      </div>
    </div>
  );
}
