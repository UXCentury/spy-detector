"use client";

import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { useLang } from "@/lib/i18nContext";
import { openExternal } from "@/lib/openExternal";

export type IocCatalogMeta = {
  upstreamUrl: string;
  upstreamSource: string;
  lastRefreshedAt?: string | null;
};

function formatWhen(
  iso: string | null | undefined,
  neverLabel: string,
): string {
  if (!iso) return neverLabel;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  return new Date(iso).toLocaleString();
}

export function IocCatalogBanner({
  className = "",
}: {
  className?: string;
}) {
  const { t } = useLang();
  const [meta, setMeta] = useState<IocCatalogMeta | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const m = await invoke<IocCatalogMeta>("get_ioc_catalog_meta");
        if (!cancelled) setMeta(m);
      } catch {
        if (!cancelled) setMeta(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const sourceLabel =
    meta?.upstreamSource === "downloaded"
      ? t("iocRefresh.sourceDownloadedLabel")
      : t("iocRefresh.sourceBundledLabel");

  return (
    <div
      className={`rounded-xl border border-(--border) bg-(--surface)/70 px-4 py-3 text-sm backdrop-blur-md ${className}`}
    >
      {!meta ? (
        <p className="text-(--muted)">{t("iocRefresh.catalogError")}</p>
      ) : (
        <dl className="grid gap-2 sm:grid-cols-2">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-(--muted)">
              {t("iocRefresh.upstream")}
            </dt>
            <dd className="mt-1 break-all font-mono text-xs text-(--foreground)">
              <a
                href={meta.upstreamUrl}
                rel="noopener noreferrer"
                className="text-(--accent-2) underline-offset-2 hover:underline"
                onClick={(e) => {
                  e.preventDefault();
                  void openExternal(meta.upstreamUrl);
                }}
              >
                {meta.upstreamUrl}
              </a>
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-(--muted)">
              {t("iocRefresh.activeSource")}
            </dt>
            <dd className="mt-1 text-(--foreground)">{sourceLabel}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-xs font-medium uppercase tracking-wide text-(--muted)">
              {t("iocRefresh.lastSuccessRefresh")}
            </dt>
            <dd className="mt-1 font-mono text-xs text-(--foreground)">
              {formatWhen(meta.lastRefreshedAt, t("iocRefresh.never"))}
            </dd>
          </div>
        </dl>
      )}
    </div>
  );
}
