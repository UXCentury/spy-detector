"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  Bell,
  Bug,
  Cog,
  EyeOff,
  FileText,
  Globe,
  Info,
  ListTree,
  Mic,
  Network,
  Play,
  Power,
  Radio,
  RefreshCw,
  ScrollText,
  Search,
  Settings,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Trash,
  Volume2,
  VolumeX,
  Lock,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useSound } from "@/components/SoundProvider";
import { useToast } from "@/components/Toast";
import type { StringKey } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { playIssueDetected } from "@/lib/sound/issueSound";

const RECENTS_KEY = "palette:recents";

export type CommandKind = "navigate" | "run" | "toggle" | "about";

export type Command = {
  id: string;
  kind: CommandKind;
  label: string;
  hint?: string;
  keywords?: string;
  shortcut?: string;
  icon?: LucideIcon;
  perform: () => void | Promise<void | "aborted">;
};

function fuzzyScore(needle: string, haystack: string): number {
  if (!needle) return 1;
  const n = needle.toLowerCase();
  const h = haystack.toLowerCase();
  let i = 0;
  let score = 0;
  let lastIdx = -1;
  for (let j = 0; j < h.length && i < n.length; j++) {
    if (h[j] === n[i]) {
      const isStart = j === 0 || h[j - 1] === " ";
      const isConsecutive = lastIdx === j - 1;
      score += isStart ? 8 : isConsecutive ? 5 : 1;
      lastIdx = j;
      i++;
    }
  }
  return i === n.length ? score : 0;
}

function loadRecentIds(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(RECENTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((x): x is string => typeof x === "string")
      .slice(0, 5);
  } catch {
    return [];
  }
}

function persistRecentIds(ids: string[]) {
  localStorage.setItem(RECENTS_KEY, JSON.stringify(ids.slice(0, 5)));
}

const KIND_ORDER: CommandKind[] = ["navigate", "run", "toggle", "about"];

type DisplaySection =
  | { sectionKind: "recent"; items: Command[] }
  | { sectionKind: CommandKind; items: Command[] };

export function CommandPalette({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const router = useRouter();
  const { t } = useLang();
  const { showToast } = useToast();
  const {
    enabled: soundEnabled,
    setEnabled: setSoundEnabled,
    soundOnIssue,
    setSoundOnIssue,
    soundOnCamera,
    setSoundOnCamera,
  } = useSound();

  const [query, setQuery] = useState("");
  const [highlight, setHighlight] = useState(0);
  const [recentIds, setRecentIds] = useState<string[]>(loadRecentIds);
  const panelRef = useRef<HTMLDivElement>(null);

  const commands = useMemo((): Command[] => {
    const nav = (
      items: {
        id: string;
        href: string;
        labelKey: StringKey;
        icon: LucideIcon;
        keywords?: string;
      }[],
    ) =>
      items.map((item) => ({
        id: item.id,
        kind: "navigate" as const,
        label: t(item.labelKey),
        icon: item.icon,
        keywords: item.keywords,
        perform: () => {
          router.push(item.href);
        },
      }));

    return [
      ...nav([
        {
          id: "nav-overview",
          href: "/",
          labelKey: "nav.overview",
          icon: Activity,
          keywords: "home dashboard",
        },
        {
          id: "nav-processes",
          href: "/processes/",
          labelKey: "nav.processes",
          icon: ListTree,
          keywords: "pid task kill quarantine",
        },
        {
          id: "nav-network",
          href: "/network/",
          labelKey: "nav.network",
          icon: Network,
          keywords: "tcp dns connection ip",
        },
        {
          id: "nav-alerts",
          href: "/alerts/",
          labelKey: "nav.alerts",
          icon: Bell,
          keywords: "notifications warnings",
        },
        {
          id: "nav-logs",
          href: "/logs/",
          labelKey: "nav.logs",
          icon: ScrollText,
          keywords: "events audit trail",
        },
        {
          id: "nav-browser-history",
          href: "/browser-history/",
          labelKey: "nav.browserHistory",
          icon: Globe,
          keywords: "url ioc browse",
        },
        {
          id: "nav-activity",
          href: "/activity/",
          labelKey: "nav.activity",
          icon: Radio,
          keywords: "live realtime thread launch",
        },
        {
          id: "nav-ignored",
          href: "/ignored/",
          labelKey: "nav.ignored",
          icon: EyeOff,
          keywords: "hide exclusions",
        },
        {
          id: "nav-allowlist",
          href: "/allowlist/",
          labelKey: "nav.allowlist",
          icon: ShieldCheck,
          keywords: "trust safe",
        },
        {
          id: "nav-startup",
          href: "/startup/",
          labelKey: "nav.startup",
          icon: Power,
          keywords: "autostart boot login registry task",
        },
        {
          id: "nav-services",
          href: "/services/",
          labelKey: "nav.services",
          icon: Cog,
          keywords: "scm service windows",
        },
        {
          id: "nav-settings",
          href: "/settings/",
          labelKey: "nav.settings",
          icon: Settings,
          keywords: "preferences language thresholds",
        },
        {
          id: "nav-settings-general",
          href: "/settings/#general",
          labelKey: "commandPalette.settings.general",
          icon: Settings2,
          keywords: "preferences language about startup",
        },
        {
          id: "nav-settings-detection",
          href: "/settings/#detection",
          labelKey: "commandPalette.settings.detection",
          icon: ShieldCheck,
          keywords: "thresholds scan amsi yara rules",
        },
        {
          id: "nav-settings-network",
          href: "/settings/#network",
          labelKey: "commandPalette.settings.network",
          icon: Globe,
          keywords: "ip feeds abuse blocklist",
        },
        {
          id: "nav-settings-notifications",
          href: "/settings/#notifications",
          labelKey: "commandPalette.settings.notifications",
          icon: Bell,
          keywords: "toast alerts native",
        },
        {
          id: "nav-settings-sound",
          href: "/settings/#sound",
          labelKey: "commandPalette.settings.sound",
          icon: Volume2,
          keywords: "audio sfx volume",
        },
        {
          id: "nav-settings-privacy",
          href: "/settings/#privacy",
          labelKey: "commandPalette.settings.privacy",
          icon: Lock,
          keywords: "terms legal data exports",
        },
        {
          id: "nav-settings-advanced",
          href: "/settings/#advanced",
          labelKey: "commandPalette.settings.advanced",
          icon: Wrench,
          keywords: "debug logs report bug diagnostics",
        },
        {
          id: "nav-rules",
          href: "/rules/",
          labelKey: "nav.rules",
          icon: ShieldQuestion,
          keywords: "signatures feeds yara",
        },
        {
          id: "nav-ioc-refresh",
          href: "/ioc-refresh/",
          labelKey: "nav.iocRefresh",
          icon: RefreshCw,
          keywords: "catalog download update",
        },
        {
          id: "nav-report-bug",
          href: "/report-bug/",
          labelKey: "nav.reportBug",
          icon: Bug,
          keywords: "issue feedback",
        },
      ]),
      {
        id: "run-scan",
        kind: "run",
        label: t("palette.cmd.runScan"),
        icon: Play,
        keywords: "findings score malware",
        perform: async () => {
          try {
            await invoke("run_scan");
            showToast(t("overview.scanFinishedToast"), "success");
          } catch (e) {
            showToast(e instanceof Error ? e.message : String(e), "error");
          }
        },
      },
      {
        id: "run-refresh-ioc",
        kind: "run",
        label: t("palette.cmd.refreshIoc"),
        icon: RefreshCw,
        keywords: "catalog indicators stalkerware",
        perform: async () => {
          try {
            const r = await invoke<{
              success: boolean;
              message: string;
            }>("refresh_ioc");
            showToast(r.message, r.success ? "success" : "error");
          } catch (e) {
            showToast(e instanceof Error ? e.message : String(e), "error");
          }
        },
      },
      {
        id: "run-refresh-feeds",
        kind: "run",
        label: t("palette.cmd.refreshFeeds"),
        icon: RefreshCw,
        keywords: "ip blocklist network malicious",
        perform: async () => {
          try {
            const r = await invoke<{ ok: boolean }>("refresh_ip_feeds");
            showToast(
              r.ok ? t("ipFeeds.refreshed") : t("ipFeeds.refreshFailed"),
              r.ok ? "success" : "info",
            );
          } catch (e) {
            showToast(e instanceof Error ? e.message : String(e), "error");
          }
        },
      },
      {
        id: "run-scan-history",
        kind: "run",
        label: t("palette.cmd.scanBrowserHistory"),
        icon: Globe,
        keywords: "browser url chrome edge",
        perform: async () => {
          try {
            const res = await invoke<{ totalFindings: number }>(
              "scan_browser_history",
            );
            showToast(
              t("browserHistory.totalFound").replace(
                "{count}",
                String(res.totalFindings),
              ),
              "info",
            );
          } catch (e) {
            showToast(e instanceof Error ? e.message : String(e), "error");
          }
        },
      },
      {
        id: "run-restart-elevated",
        kind: "run",
        label: t("palette.cmd.restartElevated"),
        icon: ShieldAlert,
        keywords: "admin uac elevation privilege",
        perform: async () => {
          try {
            await invoke("request_elevation_restart");
          } catch (e) {
            showToast(
              `${t("elevation.errorPrefix")} ${e instanceof Error ? e.message : String(e)}`,
              "error",
            );
          }
        },
      },
      {
        id: "run-clear-logs",
        kind: "run",
        label: t("palette.cmd.clearLogs"),
        icon: Trash,
        keywords: "event sqlite delete",
        perform: async () => {
          try {
            const n = await invoke<number>("count_event_log", {
              kinds: null,
              search: null,
              severities: null,
            });
            const ok = window.confirm(
              `${t("logs.confirmClearTitle")}\n\n${t("logs.confirmClearBody").replace("{count}", String(n))}`,
            );
            if (!ok) return "aborted";
            await invoke("clear_event_log");
            showToast(t("logs.cleared"), "info");
          } catch (e) {
            showToast(e instanceof Error ? e.message : String(e), "error");
          }
        },
      },
      {
        id: "run-test-sound",
        kind: "run",
        label: t("palette.cmd.testSound"),
        icon: Volume2,
        keywords: "audio alert sfx mp3",
        perform: () => {
          playIssueDetected({ force: true });
        },
      },
      {
        id: "toggle-sound",
        kind: "toggle",
        label: t("palette.cmd.toggleSound"),
        icon: soundEnabled ? Volume2 : VolumeX,
        keywords: "mute audio master",
        perform: () => {
          setSoundEnabled(!soundEnabled);
        },
      },
      {
        id: "toggle-sound-issue",
        kind: "toggle",
        label: t("palette.cmd.toggleIssueSound"),
        icon: Volume2,
        keywords: "detection alert tone",
        perform: () => {
          setSoundOnIssue(!soundOnIssue);
        },
      },
      {
        id: "toggle-sound-camera",
        kind: "toggle",
        label: t("palette.cmd.toggleCameraSound"),
        icon: Mic,
        keywords: "webcam microphone notify",
        perform: () => {
          setSoundOnCamera(!soundOnCamera);
        },
      },
      {
        id: "about-version",
        kind: "about",
        label: t("palette.cmd.versionInfo"),
        icon: Info,
        keywords: "build release mit license",
        perform: () => {
          router.push("/settings/#about");
        },
      },
      {
        id: "about-terms",
        kind: "about",
        label: t("palette.cmd.openTerms"),
        icon: FileText,
        keywords: "privacy legal disclaimer policy",
        perform: () => {
          router.push("/settings/#legal");
        },
      },
    ];
  }, [
    router,
    t,
    showToast,
    soundEnabled,
    setSoundEnabled,
    soundOnIssue,
    setSoundOnIssue,
    soundOnCamera,
    setSoundOnCamera,
  ]);

  const byId = useMemo(
    () => new Map(commands.map((c) => [c.id, c])),
    [commands],
  );

  const queryTrimmed = query.trim();

  const { flatRows, sections } = useMemo(() => {
    const haystackFor = (c: Command) =>
      [c.label, c.hint, c.keywords].filter(Boolean).join(" ");

    if (!queryTrimmed) {
      const recentItems: Command[] = [];
      const recentSeen = new Set<string>();
      for (const id of recentIds) {
        const c = byId.get(id);
        if (c && !recentSeen.has(c.id)) {
          recentItems.push(c);
          recentSeen.add(c.id);
        }
      }

      const rest: Command[] = [];
      for (const kind of KIND_ORDER) {
        for (const c of commands) {
          if (c.kind !== kind) continue;
          if (recentSeen.has(c.id)) continue;
          rest.push(c);
        }
      }

      const flat = [...recentItems, ...rest];
      const sec: DisplaySection[] = [];
      if (recentItems.length > 0) {
        sec.push({ sectionKind: "recent", items: recentItems });
      }
      const buckets = new Map<CommandKind, Command[]>();
      for (const k of KIND_ORDER) buckets.set(k, []);
      for (const c of rest) {
        buckets.get(c.kind)?.push(c);
      }
      for (const kind of KIND_ORDER) {
        const items = buckets.get(kind) ?? [];
        if (items.length > 0) sec.push({ sectionKind: kind, items });
      }
      return { flatRows: flat, sections: sec };
    }

    const scored = commands
      .map((c) => ({
        cmd: c,
        score: fuzzyScore(queryTrimmed, haystackFor(c)),
      }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score);

    const flat = scored.map((x) => x.cmd);
    const buckets = new Map<CommandKind, Command[]>();
    for (const k of KIND_ORDER) buckets.set(k, []);
    for (const c of flat) {
      buckets.get(c.kind)?.push(c);
    }
    const sec: DisplaySection[] = KIND_ORDER.map((kind) => ({
      sectionKind: kind,
      items: buckets.get(kind) ?? [],
    })).filter((s) => s.items.length > 0);

    return { flatRows: flat, sections: sec };
  }, [byId, commands, queryTrimmed, recentIds]);

  const pushRecent = useCallback((id: string) => {
    setRecentIds((prev) => {
      const next = [id, ...prev.filter((x) => x !== id)].slice(0, 5);
      persistRecentIds(next);
      return next;
    });
  }, []);

  const runCommand = useCallback(
    async (cmd: Command) => {
      try {
        const result = await Promise.resolve(cmd.perform());
        if (result === "aborted") return;
        pushRecent(cmd.id);
        onClose();
      } catch (e) {
        showToast(e instanceof Error ? e.message : String(e), "error");
      }
    },
    [onClose, pushRecent, showToast],
  );

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.isComposing) return;
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (flatRows.length === 0) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setHighlight((h) => Math.min(h + 1, flatRows.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setHighlight((h) => Math.max(h - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const cmd = flatRows[highlight];
        if (cmd) void runCommand(cmd);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isOpen, flatRows, highlight, onClose, runCommand]);

  useEffect(() => {
    if (!isOpen) return;
    void Promise.resolve().then(() => {
      setQuery("");
      setHighlight(0);
      setRecentIds(loadRecentIds());
    });
  }, [isOpen]);

  useEffect(() => {
    void Promise.resolve().then(() => {
      setHighlight((h) => {
        if (flatRows.length === 0) return 0;
        return Math.min(h, flatRows.length - 1);
      });
    });
  }, [flatRows.length, queryTrimmed]);

  useEffect(() => {
    if (!isOpen) return;
    const panel = panelRef.current;
    if (!panel) return;

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled])',
        ),
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (e.shiftKey) {
        if (active === first || !panel.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || !panel.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isOpen]);

  const sectionTitle = (k: DisplaySection["sectionKind"]): string => {
    switch (k) {
      case "recent":
        return t("palette.group.recent");
      case "navigate":
        return t("palette.group.navigate");
      case "run":
        return t("palette.group.run");
      case "toggle":
        return t("palette.group.toggle");
      case "about":
        return t("palette.group.about");
      default:
        return "";
    }
  };

  return (
    <AnimatePresence>
      {isOpen ? (
        <motion.div
          role="presentation"
          aria-hidden={!isOpen}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-220 flex items-start justify-center bg-black/60 p-4 pt-[10vh]"
          onClick={onClose}
        >
          <motion.div
            ref={panelRef}
            role="dialog"
            aria-modal="true"
            aria-label={t("palette.openHint")}
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            className="w-full max-w-xl overflow-hidden rounded-xl border border-(--border) bg-(--surface) shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-(--border) px-4 py-3">
              <Search className="size-4 shrink-0 text-(--muted)" aria-hidden />
              <input
                autoFocus
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setHighlight(0);
                }}
                placeholder={t("palette.placeholder")}
                className="min-w-0 flex-1 bg-transparent text-sm text-(--foreground) placeholder:text-(--muted) outline-none"
              />
              <span className="shrink-0 text-xs text-(--muted)">esc</span>
            </div>
            <div className="max-h-[60vh] overflow-y-auto p-1">
              {flatRows.length === 0 ? (
                <div className="px-4 py-8 text-center text-sm text-(--muted)">
                  {t("palette.empty")}
                </div>
              ) : (
                sections.map((group) => (
                  <div key={group.sectionKind}>
                    <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-(--muted)">
                      {sectionTitle(group.sectionKind)}
                    </div>
                    {group.items.map((cmd) => {
                      const Icon = cmd.icon;
                      const idx = flatRows.findIndex((c) => c.id === cmd.id);
                      const active = flatRows[highlight]?.id === cmd.id;
                      return (
                        <button
                          key={`${group.sectionKind}-${cmd.id}`}
                          type="button"
                          onMouseEnter={() => {
                            if (idx >= 0) setHighlight(idx);
                          }}
                          onClick={() => void runCommand(cmd)}
                          className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                            active
                              ? "bg-(--surface-2) text-(--foreground)"
                              : "text-(--muted) hover:text-(--foreground)"
                          }`}
                        >
                          {Icon ? (
                            <Icon className="size-4 shrink-0 opacity-90" aria-hidden />
                          ) : (
                            <span className="size-4 shrink-0" aria-hidden />
                          )}
                          <span className="min-w-0 flex-1 truncate">
                            {cmd.label}
                          </span>
                          {cmd.shortcut ? (
                            <kbd className="shrink-0 rounded bg-(--surface-2) px-1.5 py-0.5 font-mono text-[10px] text-(--muted)">
                              {cmd.shortcut}
                            </kbd>
                          ) : null}
                        </button>
                      );
                    })}
                  </div>
                ))
              )}
            </div>
            <div className="flex items-center justify-between gap-2 border-t border-(--border) px-4 py-2 text-[10px] text-(--muted)">
              <span className="truncate">
                ↑↓ {t("palette.hint.navigate")}
              </span>
              <span className="truncate">↵ {t("palette.hint.execute")}</span>
              <span className="shrink-0">esc {t("palette.hint.close")}</span>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
