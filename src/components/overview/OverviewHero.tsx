"use client";

import Link from "next/link";
import { PulseDot } from "@/components/PulseDot";
import { useLang } from "@/lib/i18nContext";

type OverviewHeroProps = {
  elevated: boolean | null;
  highSeverityCount: number;
  lastScanRelative: string;
  scanCompletedBadge: string | null;
};

export function OverviewHero({
  elevated,
  highSeverityCount,
  lastScanRelative,
  scanCompletedBadge,
}: OverviewHeroProps) {
  const { t } = useLang();
  const alertTone = highSeverityCount > 0;
  const headline = alertTone
    ? highSeverityCount === 1
      ? t("overview.heroHighSeverityOne")
      : t("overview.heroHighSeverityMany").replace(
          "{count}",
          String(highSeverityCount),
        )
    : t("overview.heroMonitoringActive");
  return (
    <div
      className={`relative overflow-hidden rounded-2xl border p-6 md:p-8 ${
        alertTone
          ? "border-(--severity-high)/35 bg-(--surface)/90"
          : "border-(--border) bg-(--surface)/90"
      }`}
      style={{
        boxShadow: alertTone
          ? "0 0 80px -20px rgba(239, 68, 68, 0.15), inset 0 1px 0 rgba(255,255,255,0.04)"
          : "0 0 80px -24px rgba(99, 102, 241, 0.18), inset 0 1px 0 rgba(255,255,255,0.04)",
      }}
    >
      <div
        className="pointer-events-none absolute -right-20 -top-20 size-64 rounded-full opacity-40 blur-3xl"
        style={{
          background: alertTone
            ? "radial-gradient(circle, var(--severity-high) 0%, transparent 70%)"
            : "radial-gradient(circle, var(--accent) 0%, transparent 72%)",
        }}
        aria-hidden
      />
      <div className="relative flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <PulseDot
              color={
                alertTone ? "var(--severity-high)" : "var(--accent-2)"
              }
            />
            <h2
              className={`text-2xl font-semibold tracking-tight md:text-3xl ${
                alertTone ? "text-(--severity-high)" : "text-(--foreground)"
              }`}
            >
              {headline}
            </h2>
            {scanCompletedBadge ? (
              <span className="rounded-full border border-(--severity-low)/35 bg-(--severity-low)/10 px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-(--severity-low)">
                {t("overview.scannedPrefix")} {scanCompletedBadge}
              </span>
            ) : null}
          </div>
          <p className="max-w-xl text-sm leading-relaxed text-(--muted)">
            {t("overview.lastScan")}{" "}
            <span className="font-medium text-(--foreground)">{lastScanRelative}</span>
            . {t("overview.heroSubtitle")}
          </p>
          <div className="flex flex-wrap gap-2 pt-1">
            {elevated === true ? (
              <span className="rounded-full border border-(--severity-low)/40 bg-(--severity-low)/10 px-3 py-1 text-xs font-medium text-(--severity-low)">
                {t("overview.elevatedMode")}
              </span>
            ) : elevated === false ? (
              <span className="rounded-full border border-(--severity-warn)/40 bg-(--severity-warn)/10 px-3 py-1 text-xs font-medium text-(--severity-warn)">
                {t("overview.limitedMode")}
              </span>
            ) : (
              <span className="rounded-full border border-(--border) px-3 py-1 text-xs text-(--muted)">
                {t("overview.checkingPrivileges")}
              </span>
            )}
            <Link
              href="/settings/"
              className="rounded-full border border-(--border) px-3 py-1 text-xs text-(--muted) transition-colors duration-200 hover:border-(--border-bright) hover:text-(--foreground)"
            >
              {t("overview.thresholdsLink")}
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
