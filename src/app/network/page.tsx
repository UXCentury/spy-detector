"use client";

import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, Globe, Radar } from "lucide-react";
import { PulseDot } from "@/components/PulseDot";
import { Skeleton } from "@/components/Skeleton";
import { StickyTable, TruncCell } from "@/components/StickyTable";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import { usePageReady } from "@/lib/PageStatus";
import type { NetworkConnectionRow } from "@/lib/types";
import type { StringKey } from "@/lib/i18n";

type ChartRow = { host: string; count: number };

function sourceBadgeClass(category: string | null): string {
  switch (category) {
    case "abuse-ch-threatfox":
    case "abuse-ch-urlhaus":
    case "abuse-ch-malwarebazaar":
      return "border border-(--severity-high)/35 bg-(--severity-high)/10 text-(--severity-high)";
    case "network-malicious":
    case "malicious-host":
      return "border border-(--severity-high)/35 bg-(--severity-high)/10 text-(--severity-high)";
    case "compromised-host":
    case "stalkerware":
      return "border border-(--severity-warn)/40 bg-(--severity-warn)/10 text-(--severity-warn)";
    case "tor-exit":
      return "border border-(--border) bg-(--surface-2)/50 text-(--muted)";
    default:
      return "border border-(--border) bg-(--surface-2)/40 text-(--foreground)";
  }
}

function categoryTitleKey(category: string | null): StringKey | null {
  switch (category) {
    case "abuse-ch-threatfox":
      return "browserHistory.categories.abuseChThreatfox";
    case "abuse-ch-urlhaus":
      return "browserHistory.categories.abuseChUrlhaus";
    case "network-malicious":
      return "ipFeeds.categories.networkMalicious";
    case "malicious-host":
      return "ipFeeds.categories.maliciousHost";
    case "compromised-host":
      return "ipFeeds.categories.compromisedHost";
    case "tor-exit":
      return "ipFeeds.categories.torExit";
    case "stalkerware":
      return "ipFeeds.categories.stalkerware";
    default:
      return null;
  }
}

function abuseNetworkTooltip(r: NetworkConnectionRow): string | undefined {
  if (!r.iocSource?.startsWith("abuse.ch")) return undefined;
  const parts: string[] = [];
  const fam = r.abuseChFamily?.trim();
  if (fam) parts.push(fam);
  const tags = r.abuseChTags?.filter(Boolean).join(", ");
  if (tags) parts.push(tags);
  if (parts.length === 0) return undefined;
  return parts.join(" · ");
}

export default function NetworkPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [rows, setRows] = useState<NetworkConnectionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [navPrimed, setNavPrimed] = useState(false);

  const fetchConnections = useCallback(async () => {
    return invoke<NetworkConnectionRow[]>("list_network_connections");
  }, []);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(() => {
      if (cancelled) return;
      setLoading(true);
      void fetchConnections()
        .then((list) => {
          if (!cancelled) setRows(list);
        })
        .catch((e) => {
          if (!cancelled) {
            showToast(e instanceof Error ? e.message : String(e), "error");
          }
        })
        .finally(() => {
          if (!cancelled) {
            setLoading(false);
            setNavPrimed(true);
          }
        });
    });
    return () => {
      cancelled = true;
    };
  }, [fetchConnections, showToast]);

  usePageReady(navPrimed);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await fetchConnections();
      setRows(list);
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setLoading(false);
    }
  }, [fetchConnections, showToast]);

  const stats = useMemo(() => {
    const uniqueHosts = new Set(rows.map((r) => r.remoteIp));
    const iocHits = rows.filter((r) => r.iocMatch).length;
    return {
      active: rows.length,
      hosts: uniqueHosts.size,
      iocHits,
    };
  }, [rows]);

  const chartData: ChartRow[] = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of rows) {
      const k = r.reverseDns?.trim() || r.remoteIp;
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    const arr = [...m.entries()]
      .map(([host, count]) => ({ host, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    return arr;
  }, [rows]);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("network.title")}</h1>
        <p className="mt-2 max-w-2xl text-sm text-(--muted)">
          {t("network.subtitle")}
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-4 backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright)">
          <div className="flex items-center gap-2 text-(--muted)">
            <Activity className="size-4 text-(--accent)" aria-hidden />
            <span className="text-xs font-medium uppercase tracking-wide">
              {t("network.activeConnections")}
            </span>
          </div>
          <div className="mt-2 text-2xl font-semibold tabular-nums">
            {loading ? <Skeleton className="h-8 w-16" /> : stats.active}
          </div>
        </div>
        <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-4 backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright)">
          <div className="flex items-center gap-2 text-(--muted)">
            <Globe className="size-4 text-(--accent-2)" aria-hidden />
            <span className="text-xs font-medium uppercase tracking-wide">
              {t("network.uniqueHosts")}
            </span>
          </div>
          <div className="mt-2 text-2xl font-semibold tabular-nums">
            {loading ? <Skeleton className="h-8 w-16" /> : stats.hosts}
          </div>
        </div>
        <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-4 backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright)">
          <div className="flex items-center gap-2 text-(--muted)">
            <Radar className="size-4 text-(--severity-warn)" aria-hidden />
            <span className="text-xs font-medium uppercase tracking-wide">
              {t("network.iocMatches")}
            </span>
          </div>
          <div className="mt-2 text-2xl font-semibold tabular-nums">
            {loading ? <Skeleton className="h-8 w-16" /> : stats.iocHits}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-4 backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium text-(--muted)">
            {t("network.topDestinations")}
          </h2>
          <button
            type="button"
            onClick={() => void load()}
            disabled={loading}
            className="rounded-lg border border-(--border) px-3 py-1.5 text-xs font-medium transition-colors duration-200 hover:bg-(--surface-2) disabled:opacity-50"
          >
            {loading ? t("network.refreshing") : t("network.refresh")}
          </button>
        </div>
        {loading ? (
          <div className="mt-4 space-y-3">
            {Array.from({ length: 8 }).map((_, i) => {
              const widths = ["78%", "62%", "88%", "45%", "70%", "55%", "92%", "38%"];
              return (
                <div key={`chart-sk-${i}`} className="flex items-center gap-3">
                  <Skeleton className="h-4 w-28 shrink-0 rounded-md" />
                  <Skeleton
                    className="h-5 rounded-md"
                    style={{ width: widths[i % widths.length] }}
                  />
                </div>
              );
            })}
          </div>
        ) : chartData.length === 0 ? (
          <p className="mt-6 text-center text-sm text-(--muted)">
            {t("network.emptyChart")}
          </p>
        ) : (
          <div className="mt-4 h-72 w-full min-w-0 shrink-0">
            <ResponsiveContainer width="100%" height={288}>
              <BarChart
                data={chartData}
                layout="vertical"
                margin={{ left: 4, right: 16, top: 8, bottom: 8 }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="var(--border)"
                  horizontal={false}
                />
                <XAxis
                  type="number"
                  stroke="var(--muted)"
                  tick={{ fill: "var(--muted)", fontSize: 11 }}
                />
                <YAxis
                  type="category"
                  dataKey="host"
                  width={132}
                  stroke="var(--muted)"
                  tick={{ fill: "var(--muted)", fontSize: 10 }}
                />
                <Tooltip
                  cursor={{ fill: "var(--surface-2)", opacity: 0.35 }}
                  contentStyle={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    color: "var(--foreground)",
                    fontSize: 12,
                  }}
                />
                <Bar
                  dataKey="count"
                  fill="var(--accent)"
                  radius={[0, 4, 4, 0]}
                  maxBarSize={22}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      <div className="overflow-hidden rounded-xl border border-(--border) bg-(--surface)/60">
        <div className="border-b border-(--border) px-4 py-3 text-sm font-medium text-(--muted)">
          {t("network.sectionConnections")}
        </div>
        <StickyTable className="sticky-table-wrap-flush">
          <table className="sticky-table min-w-[880px] text-left">
            <colgroup>
              <col style={{ width: 40 }} />
              <col style={{ width: 160 }} />
              <col style={{ width: 72 }} />
              <col style={{ minWidth: 140 }} />
              <col style={{ width: "32%" }} />
              <col style={{ width: "28%" }} />
              <col style={{ minWidth: 160 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="col-sticky-left" aria-hidden />
                <th className="col-sticky-left-2" style={{ left: 40 }}>
                  {t("network.colProcess")}
                </th>
                <th>{t("network.colPid")}</th>
                <th>{t("network.colRemote")}</th>
                <th>{t("network.colDns")}</th>
                <th>{t("network.colSource")}</th>
                <th>{t("network.colFlags")}</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 6 }).map((_, i) => (
                    <tr key={`nr-${i}`}>
                      <td colSpan={7} className="py-2">
                        <Skeleton className="h-8 w-full" />
                      </td>
                    </tr>
                  ))
                : rows.map((r, idx) => {
                    const statusColor =
                      r.iocMatch || r.beaconSuspect
                        ? "var(--severity-high)"
                        : "var(--severity-low)";
                    const sourceTitle = (() => {
                      const tip = abuseNetworkTooltip(r);
                      if (tip) return tip;
                      const ck = categoryTitleKey(r.iocCategory);
                      return ck ? t(ck) : undefined;
                    })();
                    return (
                      <tr
                        key={`${r.pid}-${r.remoteIp}-${r.remotePort}-${r.processName}-${idx}`}
                      >
                        <td className="col-sticky-left text-center align-middle">
                          <span className="inline-flex justify-center">
                            <PulseDot color={statusColor} />
                          </span>
                        </td>
                        <td className="col-sticky-left-2 font-medium" style={{ left: 40 }}>
                          {r.processName}
                        </td>
                        <td className="font-mono tabular-nums">{r.pid}</td>
                        <td className="font-mono text-xs" title={`${r.remoteIp}:${r.remotePort}`}>
                          {r.remoteIp}:{r.remotePort}
                        </td>
                        <TruncCell
                          value={r.reverseDns ?? ""}
                          className="font-mono text-xs text-(--muted)"
                        />
                        <td className="max-w-0">
                          {r.iocMatch && r.iocSource ? (
                            <span
                              title={sourceTitle}
                              className={`inline-block max-w-full truncate rounded px-1.5 py-0.5 text-[10px] font-medium ${sourceBadgeClass(r.iocCategory)}${r.iocSource.startsWith("abuse.ch") ? " underline decoration-dotted decoration-(--muted) underline-offset-2" : ""}`}
                            >
                              {r.iocSource}
                            </span>
                          ) : (
                            <span className="text-xs text-(--muted)">—</span>
                          )}
                        </td>
                        <td>
                          <div className="flex flex-wrap items-center gap-2">
                            {r.iocMatch && r.iocCategory?.startsWith("abuse-ch") ? (
                              <span className="rounded border border-(--severity-high)/35 bg-(--severity-high)/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-(--severity-high)">
                                {t("network.flags.abusech")}
                              </span>
                            ) : r.iocMatch ? (
                              <span className="rounded border border-(--severity-warn)/40 bg-(--severity-warn)/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-(--severity-warn)">
                                {t("network.flagIoc")}
                              </span>
                            ) : null}
                            {r.beaconSuspect ? (
                              <span className="inline-flex items-center gap-1.5 rounded border border-(--severity-high)/35 bg-(--severity-high)/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-(--severity-high)">
                                <PulseDot color="var(--severity-high)" />
                                {t("network.flagBeacon")}
                              </span>
                            ) : null}
                            {!r.iocMatch && !r.beaconSuspect ? (
                              <span className="text-xs text-(--muted)">—</span>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
            </tbody>
          </table>
        </StickyTable>
        {!loading && rows.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-(--muted)">
            {t("network.emptyState")}
          </div>
        ) : null}
      </div>
    </div>
  );
}
