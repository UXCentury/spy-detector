"use client";

import { invoke } from "@tauri-apps/api/core";
import { Download } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { usePageReady } from "@/lib/PageStatus";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import { IocCatalogBanner } from "@/components/IocCatalogBanner";
import { ProgressBar } from "@/components/ProgressBar";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import type {
  AbuseChRefreshSummary,
  AbuseChSourceStatus,
  AppSettings,
  IpFeedStatus,
  IpFeedsRefreshSummary,
} from "@/lib/types";

type RefreshIocResult = {
  success: boolean;
  message: string;
  entriesLoaded: number;
};

type CheckRulesUpdateResult = {
  hasUpdate: boolean;
  remoteSize?: number;
  message: string;
};

function useMinutesSince(iso: string | null): number | null {
  const [m, setM] = useState<number | null>(null);
  useEffect(() => {
    const tick = () => {
      if (!iso) {
        setM(null);
        return;
      }
      const diff = Date.now() - new Date(iso).getTime();
      if (Number.isNaN(diff)) {
        setM(null);
        return;
      }
      setM(Math.max(0, Math.floor(diff / 60000)));
    };
    tick();
    const id = window.setInterval(tick, 30_000);
    return () => window.clearInterval(id);
  }, [iso]);
  return m;
}

export default function IocRefreshPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [bannerTick, setBannerTick] = useState(0);
  const [lastRefreshed, setLastRefreshed] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [checkBusy, setCheckBusy] = useState(false);
  const [checkResult, setCheckResult] = useState<CheckRulesUpdateResult | null>(
    null,
  );
  const minutes = useMinutesSince(lastRefreshed);
  const [metaPrimed, setMetaPrimed] = useState(false);
  const [feeds, setFeeds] = useState<IpFeedStatus[]>([]);
  const [abuseFeeds, setAbuseFeeds] = useState<AbuseChSourceStatus[]>([]);

  const loadFeeds = useCallback(async () => {
    try {
      const rows = await invoke<IpFeedStatus[]>("list_ip_feeds");
      setFeeds(rows);
    } catch {
      setFeeds([]);
    }
  }, []);

  const loadAbuseFeeds = useCallback(async () => {
    try {
      const rows = await invoke<AbuseChSourceStatus[]>("list_abusech_sources");
      setAbuseFeeds(rows);
    } catch {
      setAbuseFeeds([]);
    }
  }, []);

  const loadMeta = useCallback(async () => {
    try {
      const s = await invoke<AppSettings>("get_app_settings");
      setLastRefreshed(s.iocLastRefreshedAt ?? null);
    } catch {
      setLastRefreshed(null);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(() => {
      void Promise.all([loadMeta(), loadFeeds(), loadAbuseFeeds()]).finally(() => {
        if (!cancelled) setMetaPrimed(true);
      });
    });
    return () => {
      cancelled = true;
    };
  }, [loadMeta, loadFeeds, loadAbuseFeeds]);

  usePageReady(metaPrimed);

  const bumpBanner = () => setBannerTick((n) => n + 1);

  const run = async () => {
    setBusy(true);
    try {
      const r = await invoke<RefreshIocResult>("refresh_ioc");
      const fr = await invoke<IpFeedsRefreshSummary>("refresh_ip_feeds");
      const ar = await invoke<AbuseChRefreshSummary>("refresh_abusech");
      await loadMeta();
      await loadFeeds();
      await loadAbuseFeeds();
      bumpBanner();
      const intelOk = fr.ok && ar.ok;
      const intelParts: string[] = [];
      if (!fr.ok) intelParts.push(t("ipFeeds.refreshFailed"));
      if (!ar.ok) intelParts.push(t("abusech.refreshFailed"));
      const intelNote =
        intelParts.length > 0 ? ` (${intelParts.join("; ")})` : "";

      if (r.success && intelOk) {
        showToast(
          `${r.message} ${t("ipFeeds.refreshed")} · ${t("abusech.refreshed")}`,
          "success",
        );
      } else if (r.success && !intelOk) {
        showToast(`${r.message}${intelNote}`, "info");
      } else if (!r.success && intelOk) {
        showToast(`${r.message} (${t("ipFeeds.refreshed")})`, "info");
      } else {
        showToast(`${r.message}${intelNote}`, "error");
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    setCheckBusy(true);
    setCheckResult(null);
    try {
      const r = await invoke<CheckRulesUpdateResult>("check_rules_update");
      setCheckResult(r);
      showToast(r.message, r.hasUpdate ? "success" : "info");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setCheckBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Download className="size-6 text-(--accent-2)" aria-hidden />
          <h1 className="text-2xl font-semibold tracking-tight">{t("iocRefresh.title")}</h1>
        </div>
        <p className="mt-2 text-sm text-(--muted)">{t("iocRefresh.subtitle")}</p>
      </div>

      <IocCatalogBanner key={bannerTick} />

      <div className="rounded-xl border border-(--border) bg-(--surface)/70 px-4 py-3 text-sm backdrop-blur-md">
        <h2 className="text-xs font-medium uppercase tracking-wide text-(--muted)">
          {t("ipFeeds.title")}
        </h2>
        <p className="mt-1 text-xs text-(--muted)">{t("ipFeeds.subtitle")}</p>
        <ul className="mt-3 max-h-48 space-y-2 overflow-y-auto font-mono text-[11px] text-(--foreground)">
          {feeds.map((f) => (
            <li key={f.slug} className="flex flex-wrap justify-between gap-2 border-b border-(--border)/60 pb-2 last:border-0">
              <span className="truncate">{f.label}</span>
              <span className="shrink-0 text-(--muted)">
                {t("ipFeeds.indicators").replace("{count}", String(f.indicatorCount))}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <div className="rounded-xl border border-(--border) bg-(--surface)/70 px-4 py-3 text-sm backdrop-blur-md">
        <h2 className="text-xs font-medium uppercase tracking-wide text-(--muted)">
          {t("abusech.title")}
        </h2>
        <p className="mt-1 text-xs text-(--muted)">{t("abusech.subtitle")}</p>
        <ul className="mt-3 max-h-48 space-y-2 overflow-y-auto font-mono text-[11px] text-(--foreground)">
          {abuseFeeds.map((f) => (
            <li
              key={f.slug}
              className="flex flex-wrap justify-between gap-2 border-b border-(--border)/60 pb-2 last:border-0"
            >
              <span className="truncate">{f.label}</span>
              <span className="shrink-0 text-(--muted)">
                {t("ipFeeds.indicators").replace("{count}", String(f.indicatorCount))}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-(--border) bg-(--surface)/70 px-4 py-3 text-sm backdrop-blur-md">
        <span className="text-(--muted)">{t("iocRefresh.lastRefreshed")}</span>
        {lastRefreshed ? (
          <span className="inline-flex items-baseline gap-1 rounded-full border border-(--border) bg-(--surface-2)/60 px-3 py-1 font-mono text-xs text-(--foreground)">
            <AnimatedNumber value={minutes ?? 0} className="tabular-nums" />
            <span className="text-(--muted)">{t("iocRefresh.minutesAgo")}</span>
          </span>
        ) : (
          <span className="font-mono text-xs text-(--muted)">
            {t("iocRefresh.never")}
          </span>
        )}
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
        <button
          type="button"
          disabled={busy}
          onClick={() => void run()}
          className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? t("iocRefresh.refreshing") : t("iocRefresh.refresh")}
        </button>
        <button
          type="button"
          disabled={checkBusy || busy}
          onClick={() => void check()}
          className="rounded-lg border border-(--border) bg-(--surface)/80 px-4 py-2 text-sm font-medium transition-colors duration-200 hover:bg-(--surface-2) disabled:opacity-50"
        >
          {checkBusy ? t("iocRefresh.checking") : t("iocRefresh.checkUpdate")}
        </button>
        {busy || checkBusy ? (
          <ProgressBar className="min-w-[160px] flex-1 sm:max-w-md" />
        ) : null}
      </div>

      {checkResult ? (
        <div className="rounded-xl border border-(--border) bg-(--surface)/60 px-4 py-3 text-sm">
          <div className="font-medium text-(--foreground)">
            {checkResult.hasUpdate
              ? t("iocRefresh.updateAvailable")
              : t("iocRefresh.noUpdate")}
          </div>
          <p className="mt-1 text-(--muted)">{checkResult.message}</p>
          {checkResult.remoteSize != null ? (
            <p className="mt-2 font-mono text-xs text-(--foreground)">
              Remote Content-Length: {checkResult.remoteSize}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
