"use client";

import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Bell,
  Bug,
  EyeOff,
  Globe,
  Cog,
  ListTree,
  Loader2,
  Network,
  Power,
  Radio,
  RefreshCw,
  ScrollText,
  Settings,
  ShieldCheck,
  ShieldQuestion,
  type LucideIcon,
} from "lucide-react";

type RuntimeStatus = { elevated: boolean };
import { type ReactNode, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ElevationBanner } from "@/components/ElevationBanner";
import { PulseDot } from "@/components/PulseDot";
import { TitleBar } from "@/components/TitleBar";
import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { normalizePagePath, usePageStatus } from "@/lib/PageStatus";

const nav: { href: string; labelKey: StringKey; icon: LucideIcon }[] = [
  { href: "/", labelKey: "nav.overview", icon: Activity },
  { href: "/processes/", labelKey: "nav.processes", icon: ListTree },
  { href: "/network/", labelKey: "nav.network", icon: Network },
  { href: "/alerts/", labelKey: "nav.alerts", icon: Bell },
  { href: "/logs/", labelKey: "nav.logs", icon: ScrollText },
  { href: "/browser-history/", labelKey: "nav.browserHistory", icon: Globe },
  { href: "/activity/", labelKey: "nav.activity", icon: Radio },
  { href: "/ignored/", labelKey: "nav.ignored", icon: EyeOff },
  { href: "/allowlist/", labelKey: "nav.allowlist", icon: ShieldCheck },
  { href: "/startup/", labelKey: "nav.startup", icon: Power },
  { href: "/services/", labelKey: "nav.services", icon: Cog },
  { href: "/settings/", labelKey: "nav.settings", icon: Settings },
  { href: "/rules/", labelKey: "nav.rules", icon: ShieldQuestion },
  { href: "/ioc-refresh/", labelKey: "nav.iocRefresh", icon: RefreshCw },
  { href: "/report-bug/", labelKey: "nav.reportBug", icon: Bug },
];

function monitoringSidebarCopy(
  tick: ReturnType<typeof useMonitoringTick>["tick"],
  t: (k: StringKey) => string,
): {
  dot: string;
  label: string;
  mode: string;
} {
  if (!tick) {
    return {
      dot: "var(--muted)",
      label: t("common.checking"),
      mode: "",
    };
  }
  let dot: string;
  let label: string;
  if (tick.etwProcessActive && tick.etwWin32kActive) {
    dot = "var(--severity-low)";
    label = t("appShell.monitoringActive");
  } else if (tick.etwProcessActive || tick.etwWin32kActive) {
    dot = "var(--severity-warn)";
    label = t("appShell.monitoringPartial");
  } else {
    dot = "var(--severity-high)";
    label = t("appShell.monitoringOffline");
  }
  const mode = tick.elevated ? t("common.elevated") : t("common.limited");
  return { dot, label, mode };
}

export function AppShell({ children }: { children: ReactNode }) {
  const { t } = useLang();
  const router = useRouter();
  const pathname = usePathname() ?? "/";
  const pathNorm = normalizePagePath(pathname);
  const { readyPath } = usePageStatus();
  const { tick } = useMonitoringTick();
  const { dot, label, mode } = monitoringSidebarCopy(tick, t);
  const [bannerElevated, setBannerElevated] = useState<boolean | null>(null);
  const [pendingPath, setPendingPath] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void invoke<RuntimeStatus>("get_runtime_status")
      .then((s) => {
        if (!cancelled) setBannerElevated(s.elevated);
      })
      .catch(() => {
        if (!cancelled) setBannerElevated(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (pendingPath !== null && pathNorm === pendingPath) {
    setPendingPath(null);
  }

  useEffect(() => {
    if (pendingPath === null) return;
    const id = window.setTimeout(() => {
      setPendingPath(null);
    }, 1500);
    return () => window.clearTimeout(id);
  }, [pendingPath]);

  const navigateNav = (href: string) => {
    const target = normalizePagePath(href);
    if (target === pathNorm) {
      setPendingPath(null);
      return;
    }
    setPendingPath(target);
    router.push(href);
  };

  const effectiveElevated = tick?.elevated ?? bannerElevated;
  const showElevationBanner = effectiveElevated === false;

  return (
    <div className="flex h-dvh flex-col">
      <TitleBar />
      {showElevationBanner ? <ElevationBanner /> : null}
      {/* min-h-0: flex row children need a bounded height so overflow-y-auto can scroll */}
      <div className="flex min-h-0 flex-1">
        <aside className="flex min-h-0 w-14 shrink-0 flex-col overflow-y-auto border-r border-(--border) bg-(--sidebar) py-4 md:w-56 md:px-3">
          <div className="hidden px-3 pb-5 md:block">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-(--muted)">
              {t("nav.console")}
            </div>
            <div className="mt-1 text-sm font-medium text-(--foreground)">
              {t("nav.consoleSubtitle")}
            </div>
          </div>
          <div className="flex justify-center pb-3 md:hidden" title={t("appName")}>
            <ShieldQuestion className="size-5 text-(--accent)" aria-hidden />
          </div>
          <nav className="flex flex-1 flex-col gap-0.5 px-1 md:px-0">
            {nav.map((item) => {
              const hrefPath = normalizePagePath(item.href);
              const active =
                hrefPath === "/"
                  ? pathNorm === "/"
                  : pathNorm === hrefPath || pathNorm.startsWith(`${hrefPath}/`);
              const Icon = item.icon;
              const navLabel = t(item.labelKey);
              const showPendingSpinner = pendingPath === hrefPath;
              const showRoutePriming =
                active &&
                readyPath != null &&
                readyPath !== pathNorm;
              return (
                <button
                  key={item.href}
                  type="button"
                  title={navLabel}
                  aria-current={active ? "page" : undefined}
                  aria-busy={showPendingSpinner || showRoutePriming}
                  aria-label={
                    showPendingSpinner ? `${navLabel} (${t("nav.loading")})` : navLabel
                  }
                  onClick={() => navigateNav(item.href)}
                  className={`flex w-full items-center gap-3 rounded-lg py-2.5 pl-3 text-left text-sm transition-colors duration-200 md:pr-3 ${
                    active
                      ? `border-l-2 border-(--accent) bg-(--accent)/15 text-(--foreground)${showRoutePriming ? " animate-pulse" : ""}`
                      : "border-l-2 border-transparent text-(--muted) hover:bg-(--surface-2) hover:text-(--foreground)"
                  }`}
                >
                  <Icon className="size-4 shrink-0 opacity-90" aria-hidden />
                  <span className="hidden min-w-0 flex-1 truncate md:inline">
                    {navLabel}
                  </span>
                  {showPendingSpinner ? (
                    <Loader2
                      className="ml-auto size-3.5 shrink-0 animate-spin opacity-70 md:ml-0"
                      aria-hidden
                    />
                  ) : null}
                </button>
              );
            })}
          </nav>
          <div className="mt-auto hidden border-t border-(--border) px-3 pt-4 md:block">
            <div className="flex flex-col gap-1.5 rounded-lg border border-(--border) bg-(--surface)/60 px-2.5 py-2 text-[10px] text-(--muted)">
              <div className="flex items-center gap-2">
                <PulseDot color={dot} />
                <span>
                  <span className="font-medium text-(--foreground)">{label}</span>
                </span>
              </div>
              {tick ? (
                <div className="pl-4 text-(--foreground)/90">
                  {t("common.mode")}{" "}
                  <span className="font-medium text-(--foreground)">{mode}</span>
                </div>
              ) : null}
            </div>
          </div>
        </aside>
        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto px-4 py-6 md:px-8 md:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}
