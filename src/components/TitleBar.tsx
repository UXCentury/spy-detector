"use client";

// Frameless (`decorations: false`): native caption buttons are replaced below; the window
// stays resizable via Tauri/minSize. Drag-to-move uses `data-tauri-drag-region` on the center strip.

import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import {
  AlertTriangle,
  Ban,
  Bell,
  BellOff,
  BellRing,
  Camera,
  ChevronRight,
  Copy,
  Eye,
  Mic,
  Minus,
  ScanSearch,
  Shield,
  Square,
  Waypoints,
  X,
  type LucideIcon,
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { usePathname, useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useCommandPalette } from "@/components/CommandPalette/CommandPaletteProvider";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import {
  type Notification,
  type NotificationIcon,
  useNotificationCenter,
} from "@/components/notifications/NotificationCenter";
import { PulseDot } from "@/components/PulseDot";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import {
  getAppMetadataSync,
  useAppMetadata,
} from "@/lib/hooks/useAppMetadata";

const ROUTE_KEYS: Record<string, StringKey> = {
  "/": "nav.overview",
  "/processes": "nav.processes",
  "/network": "nav.network",
  "/alerts": "nav.alerts",
  "/allowlist": "nav.allowlist",
  "/settings": "nav.settings",
  "/rules": "nav.rules",
  "/ioc-refresh": "nav.iocRefresh",
  "/report-bug": "nav.reportBug",
};

function monitoringDotColor(tick: ReturnType<typeof useMonitoringTick>["tick"]) {
  if (!tick) return "var(--muted)";
  if (tick.etwProcessActive && tick.etwWin32kActive) return "var(--severity-low)";
  if (tick.etwProcessActive || tick.etwWin32kActive) return "var(--severity-warn)";
  return "var(--severity-high)";
}

const titleBarNotifIcons: Record<NotificationIcon, LucideIcon> = {
  alert: AlertTriangle,
  shield: Shield,
  camera: Camera,
  mic: Mic,
  thread: Waypoints,
  scan: ScanSearch,
  kill: Ban,
};

const titleBarSeverityBar: Record<Notification["severity"], string> = {
  info: "bg-(--severity-low)",
  low: "bg-(--severity-low)",
  warn: "bg-(--severity-warn)",
  high: "bg-(--severity-high)",
};

function formatRelativeShort(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  return `${d}d`;
}

export function TitleBar() {
  const meta = useAppMetadata();
  const metaSync = useMemo(() => getAppMetadataSync(), []);
  const { t } = useLang();
  const { open: openCommandPalette } = useCommandPalette();
  const router = useRouter();
  const pathname = usePathname();
  const { tick } = useMonitoringTick();
  const [maximized, setMaximized] = useState(false);
  const bellWrapRef = useRef<HTMLDivElement>(null);
  const {
    notifications,
    unreadCount,
    markRead,
    markAllRead,
    clear,
    popoverOpen: bellOpen,
    setPopoverOpen: setBellOpen,
  } = useNotificationCenter();

  const visibleNotifications = useMemo(
    () => notifications.slice(0, 20),
    [notifications],
  );

  useEffect(() => {
    if (!bellOpen) return;
    const onDoc = (ev: MouseEvent) => {
      const el = bellWrapRef.current;
      if (!el?.contains(ev.target as Node)) setBellOpen(false);
    };
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") setBellOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("keydown", onKey);
    };
  }, [bellOpen, setBellOpen]);

  const crumb = useMemo(() => {
    const base = pathname.replace(/\/$/, "") || "/";
    const key = ROUTE_KEYS[base];
    return key ? t(key) : t("appName");
  }, [pathname, t]);

  const syncMaximized = useCallback(async () => {
    try {
      const w = WebviewWindow.getCurrent();
      setMaximized(await w.isMaximized());
    } catch {
      setMaximized(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => void syncMaximized());
    let unResize: (() => void) | undefined;
    let cancelled = false;
    void (async () => {
      try {
        const w = WebviewWindow.getCurrent();
        unResize = await w.onResized(() => {
          void syncMaximized();
        });
      } catch {
        /* not in Tauri */
      }
      if (cancelled && unResize) unResize();
    })();
    return () => {
      cancelled = true;
      if (unResize) unResize();
    };
  }, [syncMaximized]);

  const onMinimize = () => {
    void WebviewWindow.getCurrent().minimize();
  };

  const onToggleMaximize = () => {
    void WebviewWindow.getCurrent().toggleMaximize().then(() => syncMaximized());
  };

  const onClose = () => {
    void WebviewWindow.getCurrent().close();
  };

  const processCount = tick?.processCount ?? 0;
  const elevated = tick?.elevated ?? null;
  const isMac =
    typeof navigator !== "undefined" && /mac/i.test(navigator.platform);

  return (
    <header
      className="relative z-50 flex h-9 w-full shrink-0 items-center border-b border-(--border) bg-(--surface)/95 px-2 backdrop-blur-md"
      style={{
        backgroundImage:
          "linear-gradient(180deg, rgba(255,255,255,0.03) 0%, transparent 65%)",
      }}
    >
      <div className="flex min-w-0 flex-[0_1_auto] items-center gap-2 pl-1 md:pl-2">
        <Eye className="size-4 shrink-0 text-(--accent)" aria-hidden />
        <span className="truncate text-sm font-semibold tracking-tight text-(--foreground)">
          {t("appName")}
        </span>
        <span
          className="hidden h-4 w-px shrink-0 bg-(--border-bright)/50 sm:block"
          aria-hidden
        />
        <span className="hidden truncate text-xs text-(--muted) sm:inline">
          {crumb}
        </span>
        <button
          type="button"
          onClick={() => router.push("/settings/#about")}
          title={t("titleBar.versionTooltip")
            .replace("{version}", (meta ?? metaSync).version)
            .replace("{commit}", (meta ?? metaSync).gitCommit.slice(0, 8))}
          className="hidden h-5 items-center rounded border border-(--border) bg-(--surface-2)/50 px-1.5 text-[10px] font-mono text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) sm:inline-flex"
          data-tauri-drag-region="false"
          aria-label={t("titleBar.versionTooltip")
            .replace("{version}", (meta ?? metaSync).version)
            .replace("{commit}", (meta ?? metaSync).gitCommit.slice(0, 8))}
        >
          v{(meta ?? metaSync).version}
        </button>
      </div>

      <div
        className="flex min-h-9 min-w-8 flex-1 items-stretch"
        data-tauri-drag-region
      />

      <div className="flex flex-[0_1_auto] items-center gap-2 pr-1 md:gap-3 md:pr-2">
        <div
          className="hidden items-center gap-2 rounded-lg border border-(--border) bg-(--surface-2)/50 px-2 py-0.5 sm:flex"
          data-tauri-drag-region="false"
        >
          {elevated === true ? (
            <Shield className="size-3.5 text-(--severity-low)" aria-hidden />
          ) : elevated === false ? (
            <Shield className="size-3.5 text-(--severity-warn)" aria-hidden />
          ) : (
            <Shield className="size-3.5 text-(--muted)" aria-hidden />
          )}
          <span className="text-[10px] font-medium text-(--muted)">
            {elevated === true
              ? t("common.elevated")
              : elevated === false
                ? t("common.limited")
                : "…"}
          </span>
        </div>

        <div
          className="flex items-center gap-1.5 rounded-full border border-(--border) bg-(--surface-2)/40 px-2 py-0.5"
          data-tauri-drag-region="false"
        >
          <PulseDot color={monitoringDotColor(tick)} />
          <span className="font-mono text-[10px] tabular-nums text-(--foreground)">
            <AnimatedNumber value={processCount} />
          </span>
        </div>

        <button
          type="button"
          onClick={openCommandPalette}
          title={t("palette.openHint")}
          className="hidden h-6 items-center gap-1 rounded-md border border-(--border) bg-(--surface-2)/50 px-2 text-[10px] text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) sm:flex"
          data-tauri-drag-region="false"
        >
          <span>{isMac ? "⌘" : "Ctrl"}</span>
          <span>K</span>
        </button>

        <div
          className="relative shrink-0"
          ref={bellWrapRef}
          data-tauri-drag-region="false"
        >
          <button
            type="button"
            onClick={() => setBellOpen(!bellOpen)}
            title={t("notifications.bell.tooltip")}
            aria-label={t("notifications.unreadAria").replace(
              "{count}",
              String(unreadCount),
            )}
            aria-expanded={bellOpen}
            className="relative flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--accent)"
          >
            {unreadCount > 0 ? (
              <BellRing className="size-4" strokeWidth={2} aria-hidden />
            ) : (
              <Bell className="size-4" strokeWidth={2} aria-hidden />
            )}
            {unreadCount > 0 ? (
              <span className="absolute right-1 top-1 flex min-w-3.5 translate-x-0.5 -translate-y-0.5 items-center justify-center rounded-full bg-(--severity-high) px-0.5 text-[9px] font-bold leading-none text-white">
                {unreadCount > 9 ? "9+" : unreadCount}
              </span>
            ) : null}
          </button>

          <AnimatePresence>
            {bellOpen ? (
              <motion.div
                initial={{ opacity: 0, y: -6, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -4, scale: 0.98 }}
                transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
                className="absolute right-0 top-full z-210 mt-1 w-[min(100vw-2rem,22rem)] overflow-hidden rounded-xl border border-(--border) bg-(--surface) shadow-xl"
                role="dialog"
                aria-label={t("notifications.title")}
              >
                <div className="flex items-center justify-between gap-2 border-b border-(--border) px-3 py-2">
                  <span className="text-xs font-semibold text-(--foreground)">
                    {t("notifications.title")}
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    {unreadCount > 0 ? (
                      <button
                        type="button"
                        onClick={() => markAllRead()}
                        className="text-[11px] font-medium text-(--accent) hover:underline"
                      >
                        {t("notifications.markAllRead")}
                      </button>
                    ) : null}
                    <button
                      type="button"
                      onClick={() => clear()}
                      className="text-[11px] font-medium text-(--muted) hover:text-(--foreground) hover:underline"
                    >
                      {t("notifications.clear")}
                    </button>
                  </div>
                </div>

                <div className="max-h-[60vh] overflow-y-auto">
                  {visibleNotifications.length === 0 ? (
                    <div className="flex flex-col items-center gap-2 px-4 py-10 text-center">
                      <BellOff
                        className="size-8 text-(--muted)"
                        aria-hidden
                      />
                      <p className="text-xs text-(--muted)">
                        {t("notifications.empty")}
                      </p>
                    </div>
                  ) : (
                    <ul className="divide-y divide-(--border)/80">
                      {visibleNotifications.map((n) => {
                        const Ico = titleBarNotifIcons[n.icon];
                        const bar = titleBarSeverityBar[n.severity];
                        const rowCls = n.read
                          ? "opacity-55 hover:opacity-80"
                          : "opacity-100";
                        return (
                          <li key={n.id}>
                            <button
                              type="button"
                              onClick={() => {
                                markRead(n.id);
                                if (n.href != null && n.href !== "") {
                                  router.push(n.href);
                                }
                                setBellOpen(false);
                              }}
                              className={`flex w-full gap-2 px-2 py-2.5 text-left transition-opacity hover:bg-(--surface-2)/60 ${rowCls}`}
                            >
                              <div
                                className={`w-0.5 shrink-0 rounded-full ${bar}`}
                                aria-hidden
                              />
                              <Ico
                                className="mt-0.5 size-4 shrink-0 text-(--accent)"
                                aria-hidden
                              />
                              <div className="min-w-0 flex-1">
                                <p className="truncate text-xs font-medium text-(--foreground)">
                                  {n.title}
                                </p>
                                {n.body ? (
                                  <p className="mt-0.5 line-clamp-2 text-[11px] text-(--muted)">
                                    {n.body}
                                  </p>
                                ) : null}
                                <p className="mt-1 font-mono text-[10px] text-(--muted)">
                                  {formatRelativeShort(n.ts)}
                                </p>
                              </div>
                              <ChevronRight
                                className="size-4 shrink-0 self-center text-(--muted)"
                                aria-hidden
                              />
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              </motion.div>
            ) : null}
          </AnimatePresence>
        </div>

        <div className="flex items-center" data-tauri-drag-region="false">
          <button
            type="button"
            onClick={onMinimize}
            className="flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--accent)"
            aria-label={t("titleBar.minimize")}
          >
            <Minus className="size-3.5" strokeWidth={2} />
          </button>
          <button
            type="button"
            onClick={onToggleMaximize}
            className="flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--accent)"
            aria-label={maximized ? t("titleBar.restore") : t("titleBar.maximize")}
          >
            {maximized ? (
              <Copy className="size-3.5" strokeWidth={2} />
            ) : (
              <Square className="size-3.5" strokeWidth={2} />
            )}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--severity-high) hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--severity-high)"
            aria-label={t("common.close")}
          >
            <X className="size-3.5" strokeWidth={2} />
          </button>
        </div>
      </div>
    </header>
  );
}
