"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import Link from "next/link";
import { AnimatePresence, motion } from "framer-motion";
import {
  Bell,
  Bug,
  Copy,
  ExternalLink,
  Gauge,
  Globe,
  Info,
  Lock,
  Power,
  Radar,
  Scale,
  ScanSearch,
  Settings2,
  ShieldCheck,
  ShieldQuestion,
  SlidersHorizontal,
  RadioTower,
  ScrollText,
  Volume2,
  Wrench,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { LanguagePicker } from "@/components/LanguagePicker";
import { useNotificationCenter } from "@/components/notifications/NotificationCenter";
import { useSound } from "@/components/SoundProvider";
import { ProgressBar } from "@/components/ProgressBar";
import { ScoreGauge } from "@/components/ScoreGauge";
import { SettingSection } from "@/components/SettingSection";
import { Slider, type SliderColorStop } from "@/components/Slider";
import { Skeleton } from "@/components/Skeleton";
import { Toggle } from "@/components/Toggle";
import { useToast } from "@/components/Toast";
import {
  getAppMetadataSync,
  useAppMetadata,
} from "@/lib/hooks/useAppMetadata";
import { useScanInterval } from "@/lib/hooks/useScanInterval";
import {
  buildAllowedScanMinutes,
  formatMinutesDuration,
  nearestAllowedMinutes,
} from "@/lib/scanIntervalMinutes";
import { severityTier, tierColorVar, type SeverityTier } from "@/lib/thresholds";
import {
  isRtlLang,
  translate,
  type Lang,
  type StringKey,
} from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";
import { ONBOARDING_LANGUAGES } from "@/lib/onboardingLanguages";
import { openExternal } from "@/lib/openExternal";
import { usePageReady } from "@/lib/PageStatus";
import { playCameraOpened, playIssueDetected } from "@/lib/sound/issueSound";
import type {
  AbuseChSourceStatus,
  AppSettings,
  IpFeedStatus,
} from "@/lib/types";

const ALLOWED_SCAN_MINUTES = buildAllowedScanMinutes();
const STALKERWARE_INDICATORS_URL =
  "https://github.com/AssoEchap/stalkerware-indicators";
const DATA_FOLDER_DISPLAY = "%APPDATA%\\spy-detector\\";
const EXAMPLE_SCORES = [30, 65, 90] as const;

const SETTINGS_TAB_STORAGE_KEY = "spy-detector:settings-tab";

type SettingsTabId =
  | "general"
  | "detection"
  | "network"
  | "notifications"
  | "sound"
  | "privacy"
  | "advanced";

const SETTINGS_TAB_IDS: SettingsTabId[] = [
  "general",
  "detection",
  "network",
  "notifications",
  "sound",
  "privacy",
  "advanced",
];

const SECTION_TAB_MAP: Partial<Record<string, SettingsTabId>> = {
  language: "general",
  about: "general",
  legal: "privacy",
  rules: "detection",
};

const SETTINGS_TAB_DEFS: {
  id: SettingsTabId;
  icon: LucideIcon;
  labelKey: StringKey;
}[] = [
  { id: "general", icon: Settings2, labelKey: "settings.tabs.general" },
  { id: "detection", icon: ShieldCheck, labelKey: "settings.tabs.detection" },
  { id: "network", icon: Globe, labelKey: "settings.tabs.network" },
  { id: "notifications", icon: Bell, labelKey: "settings.tabs.notifications" },
  { id: "sound", icon: Volume2, labelKey: "settings.tabs.sound" },
  { id: "privacy", icon: Lock, labelKey: "settings.tabs.privacy" },
  { id: "advanced", icon: Wrench, labelKey: "settings.tabs.advanced" },
];

function formatAboutBuildDate(iso: string, locale: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

function thresholdTrackGradient(warn: number, alert: number): SliderColorStop[] {
  const w = Math.max(0, Math.min(100, warn));
  const a = Math.max(0, Math.min(100, alert));
  return [
    { value: 0, color: "var(--severity-low)" },
    { value: w, color: "var(--severity-warn)" },
    { value: a, color: "var(--severity-high)" },
    { value: 100, color: "var(--severity-high)" },
  ];
}

function ipFeedCategoryBadgeClass(category: string): string {
  switch (category) {
    case "network-malicious":
    case "malicious-host":
      return "border-(--severity-high)/35 bg-(--severity-high)/10 text-(--severity-high)";
    case "compromised-host":
      return "border-(--severity-warn)/40 bg-(--severity-warn)/10 text-(--severity-warn)";
    case "tor-exit":
      return "border-(--border) bg-(--surface-2)/50 text-(--muted)";
    default:
      return "border-(--border) bg-(--surface-2)/40 text-(--foreground)";
  }
}

function ipFeedCategoryLabel(category: string, t: (key: StringKey) => string): string {
  switch (category) {
    case "network-malicious":
      return t("ipFeeds.categories.networkMalicious");
    case "malicious-host":
      return t("ipFeeds.categories.maliciousHost");
    case "compromised-host":
      return t("ipFeeds.categories.compromisedHost");
    case "tor-exit":
      return t("ipFeeds.categories.torExit");
    default:
      return category;
  }
}

function tierTitle(
  tier: SeverityTier,
  t: (key: StringKey) => string,
): string {
  switch (tier) {
    case "low":
      return t("settings.thresholds.tierClean");
    case "warn":
      return t("settings.thresholds.tierWarn");
    case "high":
      return t("settings.thresholds.tierAlert");
  }
}

function defaultSettingsPayload(prev: AppSettings): AppSettings {
  return {
    ...prev,
    warnThreshold: 50,
    alertThreshold: 75,
    disabledSignatureTokens: [],
    amsiEnabled: true,
    yaraEnabled: true,
    autoScanOnLaunch: true,
    trayAlertsEnabled: true,
    diagnosticLogging: false,
    threadInjectionScannerEnabled: true,
  };
}

function CreditsPixabayLine({
  t,
  templateKey,
}: {
  t: (key: StringKey) => string;
  templateKey: StringKey;
}) {
  const template = t(templateKey);
  const parts = template.split(/(\{creator\}|\{source\})/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part === "{creator}") {
          return (
            <a
              key={i}
              href="https://pixabay.com/users/universfield-28281460/"
              rel="noopener noreferrer"
              className="text-(--accent) hover:underline"
              onClick={(e) => {
                e.preventDefault();
                void openExternal(
                  "https://pixabay.com/users/universfield-28281460/",
                );
              }}
            >
              Universfield
            </a>
          );
        }
        if (part === "{source}") {
          return (
            <a
              key={i}
              href="https://pixabay.com/sound-effects/"
              rel="noopener noreferrer"
              className="text-(--accent) hover:underline"
              onClick={(e) => {
                e.preventDefault();
                void openExternal("https://pixabay.com/sound-effects/");
              }}
            >
              Pixabay
            </a>
          );
        }
        return part;
      })}
    </>
  );
}

export default function SettingsPage() {
  const appMetaRaw = useAppMetadata();
  const appMeta = appMetaRaw ?? getAppMetadataSync();
  const { t, lang, setLang } = useLang();
  const {
    enabled: soundEnabled,
    setEnabled: setSoundEnabled,
    volume,
    setVolume,
    soundOnIssue,
    setSoundOnIssue,
    soundOnCamera,
    setSoundOnCamera,
  } = useSound();
  const {
    prefs: notifPrefs,
    setPref: setNotifPref,
    push: pushNotification,
  } = useNotificationCenter();
  const { showToast } = useToast();
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [resetConfirm, setResetConfirm] = useState(false);

  const [warnDraft, setWarnDraft] = useState(50);
  const [alertDraft, setAlertDraft] = useState(75);
  const [committedThresholds, setCommittedThresholds] = useState<{
    warn: number;
    alert: number;
  } | null>(null);

  const {
    seconds: scanIntervalSecs,
    setSeconds: setScanIntervalSecs,
    loading: scanIntervalLoading,
    error: scanIntervalError,
  } = useScanInterval();

  const [intervalDraftMinutes, setIntervalDraftMinutes] = useState(5);
  const [committedIntervalMinutes, setCommittedIntervalMinutes] = useState<
    number | null
  >(null);
  const [intervalSaving, setIntervalSaving] = useState(false);
  const [settingsPrimed, setSettingsPrimed] = useState(false);

  const [ipFeeds, setIpFeeds] = useState<IpFeedStatus[]>([]);
  const [ipFeedsBusy, setIpFeedsBusy] = useState(false);

  const [abuseChFeeds, setAbuseChFeeds] = useState<AbuseChSourceStatus[]>([]);
  const [abuseChBusy, setAbuseChBusy] = useState(false);

  const [autostart, setAutostart] = useState<boolean | null>(null);
  const [autostartUnavailable, setAutostartUnavailable] = useState(
    () => !isTauri(),
  );

  const [langPickerOpen, setLangPickerOpen] = useState(false);
  const [termsModalOpen, setTermsModalOpen] = useState(false);
  const [termsAcceptedAt, setTermsAcceptedAt] = useState<
    string | null | undefined
  >(() => (!isTauri() ? null : undefined));

  const [activeTab, setActiveTab] = useState<SettingsTabId>("general");
  const [focusedTabIndex, setFocusedTabIndex] = useState(0);
  const [tablistFocused, setTablistFocused] = useState(false);
  const sectionScrollPendingRef = useRef<string | null>(null);
  const tabSyncedRef = useRef(false);

  const applyTab = useCallback((tab: SettingsTabId) => {
    setActiveTab(tab);
    setFocusedTabIndex(Math.max(0, SETTINGS_TAB_IDS.indexOf(tab)));
    try {
      localStorage.setItem(SETTINGS_TAB_STORAGE_KEY, tab);
    } catch {
      /* ignore */
    }
    const pathBase = `${window.location.pathname}${window.location.search}`;
    history.replaceState(null, "", `${pathBase}#${tab}`);
  }, []);

  const currentLanguageRow = useMemo(
    () =>
      ONBOARDING_LANGUAGES.find((r) => r.code === lang) ??
      ONBOARDING_LANGUAGES.find((r) => r.code === "en-US")!,
    [lang],
  );

  const applyLanguage = async (code: Lang) => {
    if (code === lang) {
      setLangPickerOpen(false);
      return;
    }
    try {
      if (isTauri()) {
        await invoke("set_language", { code });
      }
      setLang(code);
      setLangPickerOpen(false);
      showToast(t("settings.language.updated"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const termsAcceptedLabel = useMemo(() => {
    if (termsAcceptedAt === undefined) return null;
    if (termsAcceptedAt == null || termsAcceptedAt === "") {
      return t("settings.legal.notAccepted");
    }
    const d = new Date(termsAcceptedAt);
    const formatted = Number.isNaN(d.getTime())
      ? termsAcceptedAt
      : d.toLocaleString(lang);
    return t("settings.legal.acceptedAt").replace("{date}", formatted);
  }, [termsAcceptedAt, lang, t]);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void invoke<string | null>("get_terms_accepted_at")
      .then((v) => {
        if (!cancelled) setTermsAcceptedAt(v ?? null);
      })
      .catch(() => {
        if (!cancelled) setTermsAcceptedAt(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const load = useCallback(async () => {
    try {
      const s = await invoke<AppSettings>("get_app_settings");
      setSettings(s);
      setWarnDraft(s.warnThreshold);
      setAlertDraft(s.alertThreshold);
      setCommittedThresholds({ warn: s.warnThreshold, alert: s.alertThreshold });
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  }, [showToast]);

  const loadIpFeeds = useCallback(async () => {
    if (!isTauri()) return;
    try {
      const rows = await invoke<IpFeedStatus[]>("list_ip_feeds");
      setIpFeeds(rows);
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  }, [showToast]);

  const loadAbuseChFeeds = useCallback(async () => {
    if (!isTauri()) return;
    try {
      const rows = await invoke<AbuseChSourceStatus[]>("list_abusech_sources");
      setAbuseChFeeds(rows);
    } catch {
      setAbuseChFeeds([]);
    }
  }, []);

  const toggleIpFeed = async (slug: string, enabled: boolean) => {
    if (!isTauri()) return;
    try {
      await invoke("set_ip_feed_enabled", { slug, enabled });
      await loadIpFeeds();
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const refreshAllIpFeeds = async () => {
    if (!isTauri()) return;
    setIpFeedsBusy(true);
    try {
      const r = await invoke<{ ok: boolean }>("refresh_ip_feeds");
      await loadIpFeeds();
      showToast(
        r.ok ? t("ipFeeds.refreshed") : t("ipFeeds.refreshFailed"),
        r.ok ? "success" : "info",
      );
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setIpFeedsBusy(false);
    }
  };

  const toggleAbuseChFeed = async (slug: string, enabled: boolean) => {
    if (!isTauri()) return;
    try {
      await invoke("set_abusech_enabled", { slug, enabled });
      await loadAbuseChFeeds();
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const refreshAbuseChFeeds = async () => {
    if (!isTauri()) return;
    setAbuseChBusy(true);
    try {
      const r = await invoke<{ ok: boolean }>("refresh_abusech");
      await loadAbuseChFeeds();
      showToast(
        r.ok ? t("abusech.refreshed") : t("abusech.refreshFailed"),
        r.ok ? "success" : "info",
      );
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setAbuseChBusy(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await load();
        await loadIpFeeds();
        await loadAbuseChFeeds();
      } finally {
        if (!cancelled) setSettingsPrimed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [load, loadIpFeeds, loadAbuseChFeeds]);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void invoke<boolean>("get_autostart_enabled")
      .then((v) => {
        if (!cancelled) {
          setAutostart(v);
          setAutostartUnavailable(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setAutostartUnavailable(true);
          setAutostart(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    void listen<boolean>("autostart_changed", (ev) => {
      if (!cancelled) setAutostart(ev.payload);
    }).then((fn) => {
      if (!cancelled) unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  usePageReady(settingsPrimed);

  useLayoutEffect(() => {
    if (!settings || tabSyncedRef.current) return;
    tabSyncedRef.current = true;
    const raw = window.location.hash.slice(1);
    let tab: SettingsTabId = "general";
    let scrollSection: string | null = null;
    if ((SETTINGS_TAB_IDS as readonly string[]).includes(raw)) {
      tab = raw as SettingsTabId;
    } else if (SECTION_TAB_MAP[raw]) {
      tab = SECTION_TAB_MAP[raw]!;
      scrollSection = raw;
    } else {
      try {
        const stored = localStorage.getItem(SETTINGS_TAB_STORAGE_KEY);
        if (
          stored &&
          (SETTINGS_TAB_IDS as readonly string[]).includes(stored)
        ) {
          tab = stored as SettingsTabId;
        }
      } catch {
        /* ignore */
      }
    }
    setActiveTab(tab);
    setFocusedTabIndex(Math.max(0, SETTINGS_TAB_IDS.indexOf(tab)));
    if (scrollSection) {
      sectionScrollPendingRef.current = scrollSection;
    } else if (!raw) {
      history.replaceState(
        null,
        "",
        `${window.location.pathname}${window.location.search}#${tab}`,
      );
    }
  }, [settings]);

  useLayoutEffect(() => {
    const id = sectionScrollPendingRef.current;
    if (!id || !settings) return;
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ block: "start", behavior: "auto" });
      sectionScrollPendingRef.current = null;
    }
  }, [activeTab, settings]);

  useEffect(() => {
    const onHashChange = () => {
      const raw = window.location.hash.slice(1);
      if ((SETTINGS_TAB_IDS as readonly string[]).includes(raw)) {
        setActiveTab(raw as SettingsTabId);
        setFocusedTabIndex(
          Math.max(0, SETTINGS_TAB_IDS.indexOf(raw as SettingsTabId)),
        );
        sectionScrollPendingRef.current = null;
        try {
          localStorage.setItem(SETTINGS_TAB_STORAGE_KEY, raw);
        } catch {
          /* ignore */
        }
        return;
      }
      if (SECTION_TAB_MAP[raw]) {
        const nextTab = SECTION_TAB_MAP[raw]!;
        setActiveTab(nextTab);
        setFocusedTabIndex(Math.max(0, SETTINGS_TAB_IDS.indexOf(nextTab)));
        sectionScrollPendingRef.current = raw;
        try {
          localStorage.setItem(SETTINGS_TAB_STORAGE_KEY, nextTab);
        } catch {
          /* ignore */
        }
      }
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (scanIntervalSecs == null) return;
    void Promise.resolve().then(() => {
      const m = nearestAllowedMinutes(
        Math.max(1, Math.round(scanIntervalSecs / 60)),
        ALLOWED_SCAN_MINUTES,
      );
      setIntervalDraftMinutes(m);
      setCommittedIntervalMinutes(m);
    });
  }, [scanIntervalSecs]);

  const thresholdsDirty = useMemo(() => {
    if (!committedThresholds) return false;
    return (
      warnDraft !== committedThresholds.warn ||
      alertDraft !== committedThresholds.alert
    );
  }, [warnDraft, alertDraft, committedThresholds]);

  const thresholdsValid = warnDraft < alertDraft;

  const intervalDirty = useMemo(() => {
    if (committedIntervalMinutes == null) return false;
    return intervalDraftMinutes !== committedIntervalMinutes;
  }, [intervalDraftMinutes, committedIntervalMinutes]);

  const intervalSliderMax = ALLOWED_SCAN_MINUTES.length - 1;
  const intervalIndex = Math.max(
    0,
    ALLOWED_SCAN_MINUTES.indexOf(intervalDraftMinutes),
  );

  const warnGradient = useMemo(
    () => thresholdTrackGradient(warnDraft, alertDraft),
    [warnDraft, alertDraft],
  );

  const saveThresholds = async () => {
    if (!settings || !thresholdsValid) return;
    setBusy(true);
    try {
      await invoke("set_app_settings", {
        value: {
          ...settings,
          warnThreshold: warnDraft,
          alertThreshold: alertDraft,
        },
      });
      setCommittedThresholds({ warn: warnDraft, alert: alertDraft });
      setSettings({
        ...settings,
        warnThreshold: warnDraft,
        alertThreshold: alertDraft,
      });
      showToast(t("settings.toast.thresholdsSaved"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const cancelThresholds = () => {
    if (!committedThresholds) return;
    setWarnDraft(committedThresholds.warn);
    setAlertDraft(committedThresholds.alert);
  };

  const saveScanInterval = async () => {
    const secs = Math.round(intervalDraftMinutes * 60);
    setIntervalSaving(true);
    try {
      await setScanIntervalSecs(secs);
      setCommittedIntervalMinutes(intervalDraftMinutes);
      showToast(t("settings.toast.intervalSaved"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setIntervalSaving(false);
    }
  };

  const cancelScanInterval = () => {
    if (committedIntervalMinutes != null) {
      setIntervalDraftMinutes(committedIntervalMinutes);
    }
  };

  const exportJson = async () => {
    setBusy(true);
    try {
      const p = await invoke<string>("export_latest_scan_json");
      showToast(t("settings.toast.exportJson").replace("{path}", p), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const exportMd = async () => {
    setBusy(true);
    try {
      const p = await invoke<string>("export_latest_scan_markdown");
      showToast(t("settings.toast.exportMd").replace("{path}", p), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const copyDataPath = async () => {
    try {
      await navigator.clipboard.writeText(DATA_FOLDER_DISPLAY);
      showToast(t("settings.toast.pathCopied"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const copyAboutDiagnostics = async () => {
    const lines = [
      `spy-detector v${appMeta.version}`,
      `commit: ${appMeta.gitCommit}`,
      `build: ${appMeta.buildDate || "—"}`,
      `target: ${appMeta.target}`,
      `tauri: ${appMeta.tauriVersion}`,
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      showToast(t("settings.about.diagnosticsCopied"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    }
  };

  const confirmResetSettings = async () => {
    if (!settings) return;
    setBusy(true);
    try {
      const payload = defaultSettingsPayload(settings);
      await invoke("set_app_settings", { value: payload });
      setSettings(payload);
      setWarnDraft(payload.warnThreshold);
      setAlertDraft(payload.alertThreshold);
      setCommittedThresholds({
        warn: payload.warnThreshold,
        alert: payload.alertThreshold,
      });
      setResetConfirm(false);
      showToast(t("settings.toast.resetDone"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  if (!settings || !committedThresholds) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-56 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    );
  }

  const previewValid = warnDraft < alertDraft;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <SlidersHorizontal
            className="size-6 text-(--accent)"
            aria-hidden
          />
          <h1 className="text-2xl font-semibold tracking-tight">{t("settings.title")}</h1>
        </div>
        <p className="mt-2 text-sm text-(--muted)">
          {t("settings.introLead")}{" "}
          <Link
            href="/rules/"
            className="text-(--accent) underline-offset-2 hover:underline"
          >
            {t("nav.rules")}
          </Link>{" "}
          {t("settings.introTrail")}
        </p>
      </div>
      <div
        className="-mx-1 overflow-x-auto px-1 pb-1"
        role="tablist"
        aria-label={t("settings.title")}
        tabIndex={0}
        aria-orientation="horizontal"
        aria-activedescendant={`settings-tab-${SETTINGS_TAB_IDS[focusedTabIndex]}`}
        onFocus={() => setTablistFocused(true)}
        onBlur={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
            setTablistFocused(false);
          }
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") {
            e.preventDefault();
            setFocusedTabIndex((i) => (i + 1) % SETTINGS_TAB_IDS.length);
          } else if (e.key === "ArrowLeft") {
            e.preventDefault();
            setFocusedTabIndex(
              (i) =>
                (i - 1 + SETTINGS_TAB_IDS.length) % SETTINGS_TAB_IDS.length,
            );
          } else if (e.key === "Home") {
            e.preventDefault();
            setFocusedTabIndex(0);
          } else if (e.key === "End") {
            e.preventDefault();
            setFocusedTabIndex(SETTINGS_TAB_IDS.length - 1);
          } else if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            applyTab(SETTINGS_TAB_IDS[focusedTabIndex]!);
          }
        }}
      >
        <div className="flex min-w-min items-end gap-0.5 border-b border-(--border)">
          {SETTINGS_TAB_DEFS.map((def, i) => {
            const Icon = def.icon;
            const selected = activeTab === def.id;
            const focusRing =
              tablistFocused && focusedTabIndex === i;
            return (
              <button
                key={def.id}
                type="button"
                role="tab"
                id={`settings-tab-${def.id}`}
                aria-selected={selected}
                tabIndex={-1}
                aria-controls={`settings-panel-${def.id}`}
                onClick={() => {
                  applyTab(def.id);
                  setFocusedTabIndex(i);
                }}
                className={`-mb-px inline-flex shrink-0 items-center gap-2 rounded-t-md border-b-2 px-4 py-2 text-xs font-medium transition-colors duration-150 ${
                  selected
                    ? "border-(--accent) bg-(--surface) text-(--foreground)"
                    : `border-transparent bg-transparent text-(--muted) hover:bg-(--surface-2) hover:text-(--foreground)${focusRing ? " ring-2 ring-(--accent)/45 ring-offset-2 ring-offset-(--background)" : ""}`
                }`}
              >
                <Icon className="size-3.5 shrink-0 opacity-90" aria-hidden />
                {t(def.labelKey)}
              </button>
            );
          })}
        </div>
      </div>
      {activeTab === "general" ? (
        <div
          role="tabpanel"
          id="settings-panel-general"
          aria-labelledby="settings-tab-general"
          className="space-y-8"
        >

      <SettingSection
        id="language"
        icon={Globe}
        title={t("settings.language.title")}
        description={t("settings.language.description")}
      >
        <div className="rounded-lg border border-(--border) bg-(--surface-2)/40 p-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-center gap-3">
              <span
                className="shrink-0 text-3xl leading-none"
                style={{
                  fontFamily:
                    '"Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", sans-serif',
                }}
                aria-hidden
              >
                {currentLanguageRow.flag}
              </span>
              <div className="min-w-0">
                <p className="text-sm font-medium text-(--foreground)">
                  {currentLanguageRow.native}
                </p>
                <p className="text-xs text-(--muted)">
                  {currentLanguageRow.english}
                </p>
              </div>
            </div>
            <motion.button
              type="button"
              onClick={() => setLangPickerOpen(true)}
              whileTap={{ scale: 0.98 }}
              className="inline-flex shrink-0 items-center justify-center rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
            >
              {t("settings.language.change")}
            </motion.button>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2 border-t border-(--border) pt-4">
          <motion.button
            type="button"
            onClick={() => setTermsModalOpen(true)}
            whileTap={{ scale: 0.98 }}
            className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
          >
            {t("settings.legal.viewTerms")}
          </motion.button>
        </div>
      </SettingSection>

      <SettingSection id="about" icon={Info} title={t("settings.about.title")}>
        <div className="space-y-4 text-sm leading-relaxed">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-(--muted)">{t("settings.about.version")}</dt>
            <dd className="font-mono text-lg font-semibold tracking-tight text-(--foreground)">
              v{appMeta.version}
            </dd>
            <dt className="text-(--muted)">{t("settings.about.buildDate")}</dt>
            <dd className="font-mono text-(--foreground)">
              {formatAboutBuildDate(appMeta.buildDate, lang)}
            </dd>
            <dt className="text-(--muted)">{t("settings.about.gitCommit")}</dt>
            <dd className="font-mono text-(--foreground)">{appMeta.gitCommit}</dd>
            <dt className="text-(--muted)">{t("settings.about.target")}</dt>
            <dd className="font-mono text-(--foreground)">{appMeta.target}</dd>
            <dt className="text-(--muted)">{t("settings.about.tauriVersion")}</dt>
            <dd className="font-mono text-(--foreground)">{appMeta.tauriVersion}</dd>
          </dl>
          <motion.button
            type="button"
            onClick={() => void copyAboutDiagnostics()}
            whileTap={{ scale: 0.98 }}
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm transition-colors duration-150 hover:bg-(--surface-2)"
          >
            <Copy className="size-4 text-(--accent)" aria-hidden />
            {t("settings.about.copyDiagnostics")}
          </motion.button>
          <p className="text-(--muted)">{t("settings.about.tagline")}</p>
          <div className="flex flex-wrap items-center gap-2 text-(--foreground)">
            <span className="font-medium">{t("settings.about.licenseLabel")}</span>
            <span>{t("settings.about.license")}</span>
            <button
              type="button"
              onClick={() =>
                void openExternal("https://opensource.org/licenses/MIT")
              }
              className="inline-flex items-center gap-1 rounded-md p-1 text-(--accent) transition-colors hover:bg-(--surface-2)"
              aria-label="Open MIT License in new tab"
            >
              <ExternalLink className="size-4" aria-hidden />
            </button>
          </div>
          <p className="text-(--muted)">
            <span className="font-medium text-(--foreground)">
              {t("settings.about.madeBy")}
            </span>{" "}
            <a
              href="https://uxcentury.com"
              rel="noopener noreferrer"
              className="font-medium text-(--accent) underline-offset-2 hover:underline"
              onClick={(e) => {
                e.preventDefault();
                void openExternal("https://uxcentury.com");
              }}
            >
              UXC LLC
            </a>
          </p>
          <p className="text-(--muted)">{t("settings.about.mission")}</p>
          <div className="space-y-2 border-t border-(--border) pt-4">
            <p className="text-sm font-medium text-(--foreground)">
              {t("settings.about.credits")}
            </p>
            <ul className="list-inside list-disc space-y-1 text-sm text-(--muted)">
              <li>
                <CreditsPixabayLine t={t} templateKey="settings.about.creditsIssue" />
              </li>
              <li>
                <CreditsPixabayLine t={t} templateKey="settings.about.creditsCamera" />
              </li>
            </ul>
          </div>
          <div className="space-y-2 border-t border-(--border) pt-4">
            <p className="break-all font-mono text-xs text-(--muted)">
              {STALKERWARE_INDICATORS_URL}
            </p>
            <motion.button
              type="button"
              onClick={() => void openExternal(STALKERWARE_INDICATORS_URL)}
              whileTap={{ scale: 0.98 }}
              className="rounded-lg border border-(--border) px-4 py-2 text-sm text-(--foreground) transition-colors duration-150 hover:bg-(--surface-2)"
            >
              {t("settings.about.openIndicators")}
            </motion.button>
          </div>
        </div>
      </SettingSection>

      <SettingSection icon={Power} title={t("settings.startup.title")}>
        {autostartUnavailable ? (
          <p className="text-xs text-(--muted)">{t("settings.startup.unavailable")}</p>
        ) : null}
        <Toggle
          checked={Boolean(autostart)}
          onChange={(next) =>
            void (async () => {
              if (!isTauri() || autostartUnavailable) return;
              try {
                await invoke("set_autostart_enabled", { enabled: next });
                setAutostart(next);
                showToast(
                  next ? t("settings.startup.toggleOn") : t("settings.startup.toggleOff"),
                  "success",
                );
              } catch (e) {
                showToast(e instanceof Error ? e.message : String(e), "error");
              }
            })()
          }
          disabled={autostartUnavailable || autostart === null}
          label={t("settings.startup.runOnBoot")}
          description={t("settings.startup.runOnBootDescription")}
        />
      </SettingSection>

        </div>
      ) : null}

      {activeTab === "detection" ? (
        <div
          role="tabpanel"
          id="settings-panel-detection"
          aria-labelledby="settings-tab-detection"
          className="space-y-8"
        >
      <SettingSection
        icon={Gauge}
        title={t("settings.thresholds.title")}
        description={t("settings.thresholds.description")}
      >
        <Slider
          label={t("settings.thresholds.warn")}
          min={0}
          max={100}
          step={5}
          value={warnDraft}
          onChange={setWarnDraft}
          colorStops={warnGradient}
        />
        <Slider
          label={t("settings.thresholds.alert")}
          min={0}
          max={100}
          step={5}
          value={alertDraft}
          onChange={setAlertDraft}
          colorStops={warnGradient}
        />

        {!thresholdsValid ? (
          <p className="text-xs text-(--severity-high)">
            {t("settings.thresholds.invalidOrder")}
          </p>
        ) : null}

        <div className="rounded-lg border border-(--border) bg-(--surface-2)/40 p-4">
          <p className="text-xs font-medium text-(--muted)">
            {t("settings.thresholds.livePreview")}
          </p>
          <p className="mt-1 text-[11px] text-(--muted)">
            {t("settings.thresholds.previewCaption")}
          </p>
          <div className="relative mt-4">
            {previewValid ? (
              <div className="relative flex h-7 w-full overflow-hidden rounded-full">
                <div
                  className="h-full bg-(--severity-low)"
                  style={{ width: `${warnDraft}%` }}
                />
                <div
                  className="h-full bg-(--severity-warn)"
                  style={{ width: `${alertDraft - warnDraft}%` }}
                />
                <div
                  className="h-full bg-(--severity-high)"
                  style={{ width: `${100 - alertDraft}%` }}
                />
                {EXAMPLE_SCORES.map((score) => {
                  const tier = severityTier(score, warnDraft, alertDraft);
                  return (
                    <span
                      key={score}
                      className="absolute top-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-(--background)"
                      style={{
                        left: `${score}%`,
                        backgroundColor: tierColorVar(tier),
                      }}
                    />
                  );
                })}
              </div>
            ) : (
              <div className="flex h-7 w-full items-center justify-center rounded-full bg-(--surface-2) text-xs text-(--muted)">
                {t("settings.thresholds.setValidPreview")}
              </div>
            )}
          </div>
          {previewValid ? (
            <div className="mt-6 flex flex-wrap justify-around gap-6">
              {EXAMPLE_SCORES.map((score) => {
                const tier = severityTier(score, warnDraft, alertDraft);
                return (
                  <div
                    key={score}
                    className="flex min-w-[72px] flex-col items-center gap-2"
                  >
                    <ScoreGauge
                      score={score}
                      warnThreshold={warnDraft}
                      alertThreshold={alertDraft}
                      size="sm"
                    />
                    <span
                      className="text-[10px] font-semibold uppercase tracking-wide"
                      style={{ color: tierColorVar(tier) }}
                    >
                      {tierTitle(tier, t)}
                    </span>
                    <span className="font-mono text-[10px] tabular-nums text-(--muted)">
                      {t("settings.thresholds.scoreLabel")} {score}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : null}
        </div>

        <AnimatePresence>
          {thresholdsDirty ? (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 6 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="flex flex-wrap items-center gap-2 border-t border-(--border) pt-4"
            >
              <motion.button
                type="button"
                disabled={busy}
                onClick={cancelThresholds}
                whileTap={{ scale: 0.98 }}
                className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
              >
                {t("settings.thresholds.cancel")}
              </motion.button>
              <motion.button
                type="button"
                disabled={busy || !thresholdsValid}
                onClick={() => void saveThresholds()}
                whileTap={{ scale: 0.98 }}
                className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-150 hover:opacity-90 disabled:opacity-50"
              >
                {t("settings.thresholds.save")}
              </motion.button>
              {busy ? <ProgressBar className="max-w-xs flex-1" /> : null}
            </motion.div>
          ) : null}
        </AnimatePresence>
      </SettingSection>

      <SettingSection
        icon={Radar}
        title={t("settings.monitoring.title")}
        description={t("settings.monitoring.description")}
      >
        <div>
          <Slider
            label={t("settings.monitoring.intervalLabel")}
            min={0}
            max={intervalSliderMax}
            step={1}
            value={intervalIndex}
            onChange={(idx) =>
              setIntervalDraftMinutes(ALLOWED_SCAN_MINUTES[idx] ?? 5)
            }
            colorStops={[
              { value: 0, color: "var(--accent-2)" },
              { value: 100, color: "var(--accent)" },
            ]}
            valueFormatter={(idx) =>
              formatMinutesDuration(ALLOWED_SCAN_MINUTES[idx] ?? 5)
            }
            formatMin={() =>
              formatMinutesDuration(ALLOWED_SCAN_MINUTES[0] ?? 1)
            }
            formatMax={() =>
              formatMinutesDuration(
                ALLOWED_SCAN_MINUTES[ALLOWED_SCAN_MINUTES.length - 1] ?? 1440,
              )
            }
            disabled={scanIntervalLoading || intervalSaving}
          />
          <div className="mt-3 flex flex-wrap justify-between gap-x-2 gap-y-1 font-mono text-[10px] text-(--muted)">
            {[1, 5, 15, 30, 60, 120, 360, 720, 1440].map((m) => (
              <span key={m}>{formatMinutesDuration(m)}</span>
            ))}
          </div>
        </div>
        {scanIntervalError ? (
          <p className="text-xs text-(--severity-high)">{scanIntervalError}</p>
        ) : null}

        <Toggle
          checked={settings.autoScanOnLaunch ?? true}
          onChange={(v) =>
            void (async () => {
              setBusy(true);
              try {
                const next = { ...settings, autoScanOnLaunch: v };
                await invoke("set_app_settings", { value: next });
                setSettings(next);
                if (isTauri()) {
                  try {
                    await emit("app_settings_changed", next);
                  } catch {
                    /* listeners are best-effort */
                  }
                }
                showToast(t("settings.toast.monitoringSaved"), "success");
              } catch (e) {
                showToast(e instanceof Error ? e.message : String(e), "error");
              } finally {
                setBusy(false);
              }
            })()
          }
          disabled={busy || !isTauri()}
          label={t("settings.monitoring.autoScan")}
          description={t("settings.monitoring.autoScanDesc")}
        />
        <Toggle
          checked={settings.trayAlertsEnabled ?? true}
          onChange={(v) =>
            void (async () => {
              setBusy(true);
              try {
                const next = { ...settings, trayAlertsEnabled: v };
                await invoke("set_app_settings", { value: next });
                setSettings(next);
                if (isTauri()) {
                  try {
                    await emit("app_settings_changed", next);
                  } catch {
                    /* listeners are best-effort */
                  }
                }
                showToast(t("settings.toast.monitoringSaved"), "success");
              } catch (e) {
                showToast(e instanceof Error ? e.message : String(e), "error");
              } finally {
                setBusy(false);
              }
            })()
          }
          disabled={busy || !isTauri()}
          label={t("settings.monitoring.trayNotifications")}
          description={t("settings.monitoring.trayNotificationsDesc")}
        />

        <AnimatePresence>
          {intervalDirty ? (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 6 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="flex flex-wrap items-center gap-2 border-t border-(--border) pt-4"
            >
              <motion.button
                type="button"
                disabled={intervalSaving || scanIntervalLoading}
                onClick={cancelScanInterval}
                whileTap={{ scale: 0.98 }}
                className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
              >
                {t("settings.monitoring.cancel")}
              </motion.button>
              <motion.button
                type="button"
                disabled={intervalSaving || scanIntervalLoading}
                onClick={() => void saveScanInterval()}
                whileTap={{ scale: 0.98 }}
                className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-150 hover:opacity-90 disabled:opacity-50"
              >
                {t("settings.monitoring.save")}
              </motion.button>
              {intervalSaving ? (
                <ProgressBar className="max-w-xs flex-1" />
              ) : null}
            </motion.div>
          ) : null}
        </AnimatePresence>
      </SettingSection>

      <SettingSection
        icon={ScanSearch}
        title={t("settings.detection.title")}
      >
        <Toggle
          checked={settings.amsiEnabled ?? true}
          onChange={(v) =>
            void (async () => {
              setBusy(true);
              try {
                await invoke("set_app_settings", {
                  value: { ...settings, amsiEnabled: v },
                });
                setSettings({ ...settings, amsiEnabled: v });
                showToast(t("settings.toast.detectionSaved"), "success");
              } catch (e) {
                showToast(e instanceof Error ? e.message : String(e), "error");
              } finally {
                setBusy(false);
              }
            })()
          }
          disabled={busy || !isTauri()}
          label={t("settings.detection.amsi")}
        />
        <Toggle
          checked={settings.yaraEnabled ?? true}
          onChange={(v) =>
            void (async () => {
              setBusy(true);
              try {
                await invoke("set_app_settings", {
                  value: { ...settings, yaraEnabled: v },
                });
                setSettings({ ...settings, yaraEnabled: v });
                showToast(t("settings.toast.detectionSaved"), "success");
              } catch (e) {
                showToast(e instanceof Error ? e.message : String(e), "error");
              } finally {
                setBusy(false);
              }
            })()
          }
          disabled={busy || !isTauri()}
          label={t("settings.detection.yara")}
        />
        <Toggle
          checked={settings.threadInjectionScannerEnabled ?? true}
          onChange={(v) =>
            void (async () => {
              setBusy(true);
              try {
                await invoke("set_app_settings", {
                  value: { ...settings, threadInjectionScannerEnabled: v },
                });
                setSettings({ ...settings, threadInjectionScannerEnabled: v });
                showToast(t("settings.toast.detectionSaved"), "success");
              } catch (e) {
                showToast(e instanceof Error ? e.message : String(e), "error");
              } finally {
                setBusy(false);
              }
            })()
          }
          disabled={busy || !isTauri()}
          label={t("settings.detection.threadInjection.title")}
          description={t("settings.detection.threadInjection.description")}
        />
      </SettingSection>

      <SettingSection
        id="rules"
        icon={ShieldQuestion}
        title={t("nav.rules")}
        description={t("rules.subtitle")}
      >
        <Link
          href="/rules/"
          className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-150 hover:opacity-90"
        >
          {t("nav.rules")}
          <ExternalLink className="size-4 shrink-0 opacity-90" aria-hidden />
        </Link>
      </SettingSection>

        </div>
      ) : null}

      {activeTab === "network" ? (
        <div
          role="tabpanel"
          id="settings-panel-network"
          aria-labelledby="settings-tab-network"
          className="space-y-8"
        >

      <SettingSection
        icon={RadioTower}
        title={t("ipFeeds.title")}
        description={t("ipFeeds.subtitle")}
      >
        <p className="text-xs text-(--muted)">{t("ipFeeds.fireholHint")}</p>
        <div className="flex flex-wrap items-center gap-3 border-b border-(--border) pb-4">
          <motion.button
            type="button"
            disabled={ipFeedsBusy || !isTauri()}
            onClick={() => void refreshAllIpFeeds()}
            whileTap={{ scale: 0.98 }}
            className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-150 hover:opacity-90 disabled:opacity-50"
          >
            {ipFeedsBusy ? t("network.refreshing") : t("ipFeeds.refreshAll")}
          </motion.button>
          {ipFeedsBusy ? (
            <ProgressBar className="min-w-[140px] max-w-xs flex-1" />
          ) : null}
        </div>
        <div className="space-y-4">
          {ipFeeds.map((f) => {
            const whenLabel = f.lastRefreshedAt
              ? t("ipFeeds.lastRefreshed").replace(
                  "{when}",
                  new Date(f.lastRefreshedAt).toLocaleString(lang),
                )
              : t("ipFeeds.lastRefreshed").replace("{when}", t("ipFeeds.never"));
            return (
              <div
                key={f.slug}
                className="flex flex-col gap-3 rounded-lg border border-(--border) bg-(--surface-2)/35 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-(--foreground)">
                      {f.label}
                    </span>
                    <span
                      className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${ipFeedCategoryBadgeClass(f.category)}`}
                    >
                      {ipFeedCategoryLabel(f.category, t)}
                    </span>
                  </div>
                  <p className="text-[11px] text-(--muted)">{whenLabel}</p>
                  <p className="text-[11px] text-(--muted)">
                    {t("ipFeeds.indicators").replace(
                      "{count}",
                      String(f.indicatorCount),
                    )}
                  </p>
                </div>
                <div className="flex shrink-0 flex-col items-stretch gap-3 sm:items-end">
                  <Toggle
                    checked={f.enabled}
                    onChange={(v) => void toggleIpFeed(f.slug, v)}
                    disabled={!isTauri() || ipFeedsBusy}
                    label=""
                    ariaLabel={`${f.label} feed`}
                  />
                  <a
                    href={f.upstreamUrl}
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-(--accent-2) underline-offset-2 hover:underline"
                    onClick={(e) => {
                      e.preventDefault();
                      void openExternal(f.upstreamUrl);
                    }}
                  >
                    <ExternalLink className="size-3.5 shrink-0" aria-hidden />
                    {t("ipFeeds.upstream")}
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      </SettingSection>

      <SettingSection
        icon={Radar}
        title={t("abusech.title")}
        description={t("abusech.subtitle")}
      >
        <p className="text-xs text-(--muted)">
          <a
            href="https://abuse.ch/"
            rel="noopener noreferrer"
            className="text-(--accent-2) underline-offset-2 hover:underline"
            onClick={(e) => {
              e.preventDefault();
              void openExternal("https://abuse.ch/");
            }}
          >
            {t("abusech.home")}
          </a>
        </p>
        <div className="flex flex-wrap items-center gap-3 border-b border-(--border) pb-4">
          <motion.button
            type="button"
            disabled={abuseChBusy || !isTauri()}
            onClick={() => void refreshAbuseChFeeds()}
            whileTap={{ scale: 0.98 }}
            className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-150 hover:opacity-90 disabled:opacity-50"
          >
            {abuseChBusy ? t("network.refreshing") : t("abusech.refreshFeeds")}
          </motion.button>
          {abuseChBusy ? (
            <ProgressBar className="min-w-[140px] max-w-xs flex-1" />
          ) : null}
        </div>
        <div className="space-y-4">
          {abuseChFeeds.map((f) => {
            const descKey =
              f.slug === "threatfox"
                ? ("abusech.threatfox.description" as const)
                : f.slug === "urlhaus"
                  ? ("abusech.urlhaus.description" as const)
                  : ("abusech.mb.description" as const);
            const whenLabel = f.lastRefreshedAt
              ? t("ipFeeds.lastRefreshed").replace(
                  "{when}",
                  new Date(f.lastRefreshedAt).toLocaleString(lang),
                )
              : t("ipFeeds.lastRefreshed").replace("{when}", t("ipFeeds.never"));
            return (
              <div
                key={f.slug}
                className="flex flex-col gap-3 rounded-lg border border-(--border) bg-(--surface-2)/35 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-(--foreground)">
                      {f.label}
                    </span>
                  </div>
                  <p className="text-[11px] text-(--muted)">{whenLabel}</p>
                  <p className="text-[11px] text-(--muted)">{t(descKey)}</p>
                  <p className="text-[11px] text-(--muted)">
                    {t("ipFeeds.indicators").replace(
                      "{count}",
                      String(f.indicatorCount),
                    )}
                  </p>
                </div>
                <div className="flex shrink-0 flex-col items-stretch gap-3 sm:items-end">
                  <Toggle
                    checked={f.enabled}
                    onChange={(v) => void toggleAbuseChFeed(f.slug, v)}
                    disabled={!isTauri() || abuseChBusy}
                    label=""
                    ariaLabel={`${f.label} abuse.ch`}
                  />
                  <a
                    href={f.upstreamUrl}
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-(--accent-2) underline-offset-2 hover:underline"
                    onClick={(e) => {
                      e.preventDefault();
                      void openExternal(f.upstreamUrl);
                    }}
                  >
                    <ExternalLink className="size-3.5 shrink-0" aria-hidden />
                    {t("ipFeeds.upstream")}
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      </SettingSection>

        </div>
      ) : null}

      {activeTab === "notifications" ? (
        <div
          role="tabpanel"
          id="settings-panel-notifications"
          aria-labelledby="settings-tab-notifications"
          className="space-y-8"
        >

      <SettingSection icon={Bell} title={t("settings.notifications.title")}>
        <Toggle
          checked={notifPrefs.inApp}
          onChange={(v) => setNotifPref("inApp", v)}
          label={t("settings.notifications.inApp")}
        />
        <Toggle
          checked={notifPrefs.native}
          onChange={(v) => setNotifPref("native", v)}
          label={t("settings.notifications.native")}
        />
        <Toggle
          checked={notifPrefs.cameraMic}
          onChange={(v) => setNotifPref("cameraMic", v)}
          label={t("settings.notifications.cameraMic")}
        />
        <Toggle
          checked={notifPrefs.actions}
          onChange={(v) => setNotifPref("actions", v)}
          label={t("settings.notifications.actions")}
        />
        <Toggle
          checked={notifPrefs.autostart}
          onChange={(v) => setNotifPref("autostart", v)}
          label={t("settings.notifications.autostart")}
        />
        <motion.button
          type="button"
          onClick={() =>
            pushNotification({
              severity: "high",
              icon: "shield",
              title: t("settings.notifications.test"),
              body: "This is a test",
              href: "/logs/",
            })
          }
          whileTap={{ scale: 0.98 }}
          className="inline-flex items-center justify-center rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
        >
          {t("settings.notifications.test")}
        </motion.button>
      </SettingSection>

        </div>
      ) : null}

      {activeTab === "sound" ? (
        <div
          role="tabpanel"
          id="settings-panel-sound"
          aria-labelledby="settings-tab-sound"
          className="space-y-8"
        >

      <SettingSection icon={Volume2} title={t("settings.sound.title")}>
        <div className="min-w-0">
          <Toggle
            checked={soundEnabled}
            onChange={setSoundEnabled}
            label={t("settings.sound.enable")}
            description={t("settings.sound.enableDescription")}
          />
        </div>
        <Slider
          label={t("settings.sound.volume")}
          min={0}
          max={100}
          step={1}
          value={Math.round(volume * 100)}
          onChange={(v) => setVolume(v / 100)}
          disabled={!soundEnabled}
          colorStops={[
            { value: 0, color: "var(--muted)" },
            { value: 100, color: "var(--accent)" },
          ]}
        />
        <div className="mt-4 space-y-4 border-l-2 border-(--border) pl-4">
          <div className="flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-1 basis-[min(100%,280px)]">
              <Toggle
                checked={soundOnIssue}
                onChange={setSoundOnIssue}
                disabled={!soundEnabled}
                label={t("settings.sound.subOnIssue")}
              />
            </div>
            <motion.button
              type="button"
              disabled={!soundEnabled}
              onClick={() => playIssueDetected({ volume, force: true })}
              whileTap={{ scale: 0.98 }}
              title={t("settings.sound.testIssue")}
              aria-label={t("settings.sound.testIssue")}
              className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-(--border) text-(--foreground) transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
            >
              <Volume2 className="size-4 text-(--accent)" aria-hidden />
            </motion.button>
          </div>
          <div className="flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-1 basis-[min(100%,280px)]">
              <Toggle
                checked={soundOnCamera}
                onChange={setSoundOnCamera}
                disabled={!soundEnabled}
                label={t("settings.sound.subOnCamera")}
              />
            </div>
            <motion.button
              type="button"
              disabled={!soundEnabled}
              onClick={() => playCameraOpened({ volume, force: true })}
              whileTap={{ scale: 0.98 }}
              title={t("settings.sound.testCamera")}
              aria-label={t("settings.sound.testCamera")}
              className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-(--border) text-(--foreground) transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
            >
              <Volume2 className="size-4 text-(--accent)" aria-hidden />
            </motion.button>
          </div>
        </div>
      </SettingSection>

        </div>
      ) : null}

      {activeTab === "privacy" ? (
        <div
          role="tabpanel"
          id="settings-panel-privacy"
          aria-labelledby="settings-tab-privacy"
          className="space-y-8"
        >

      <SettingSection id="legal" icon={Scale} title={t("settings.legal.title")}>
        <div className="space-y-4">
          <p className="text-sm text-(--muted)">
            {termsAcceptedLabel === null
              ? t("common.loading")
              : termsAcceptedLabel}
          </p>
          <motion.button
            type="button"
            onClick={() => setTermsModalOpen(true)}
            whileTap={{ scale: 0.98 }}
            className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
          >
            {t("settings.legal.viewTerms")}
          </motion.button>
        </div>
      </SettingSection>

      <SettingSection
        icon={ShieldCheck}
        title={t("settings.privacy.title")}
        description={t("settings.privacy.description")}
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="text-xs text-(--muted)">
              {t("settings.privacy.localFolder")}
            </p>
            <p className="mt-1 break-all font-mono text-sm text-(--foreground)">
              {DATA_FOLDER_DISPLAY}
            </p>
          </div>
          <motion.button
            type="button"
            onClick={() => void copyDataPath()}
            whileTap={{ scale: 0.98 }}
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm transition-colors duration-150 hover:bg-(--surface-2)"
          >
            <Copy className="size-4 text-(--accent)" aria-hidden />
            {t("settings.privacy.copyPath")}
          </motion.button>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-(--border) pt-4">
          {!resetConfirm ? (
            <motion.button
              type="button"
              disabled={busy}
              onClick={() => setResetConfirm(true)}
              whileTap={{ scale: 0.98 }}
              className="rounded-lg border border-(--severity-high)/50 bg-(--severity-high)/10 px-4 py-2 text-sm font-medium text-(--severity-high) transition-colors duration-150 hover:bg-(--severity-high)/18 disabled:opacity-50"
            >
              {t("settings.privacy.resetSettings")}
            </motion.button>
          ) : (
            <>
              <motion.button
                type="button"
                disabled={busy}
                onClick={() => void confirmResetSettings()}
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                whileTap={{ scale: 0.98 }}
                className="rounded-lg bg-(--severity-high) px-4 py-2 text-sm font-medium text-white transition-opacity duration-150 hover:opacity-90 disabled:opacity-50"
              >
                {t("settings.privacy.confirmReset")}
              </motion.button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setResetConfirm(false)}
                className="rounded-lg border border-(--border) px-4 py-2 text-sm transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
              >
                {t("settings.privacy.cancel")}
              </button>
            </>
          )}
        </div>

        <div className="border-t border-(--border) pt-4">
          <p className="text-xs text-(--muted)">
            {t("settings.privacy.exportsBlurb")}{" "}
            <span className="font-mono text-(--foreground)">
              %APPDATA%\spy-detector\exports\
            </span>
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => void exportJson()}
              className="rounded-lg border border-(--border) px-4 py-2 text-sm transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
            >
              {t("settings.privacy.exportJson")}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void exportMd()}
              className="rounded-lg border border-(--border) px-4 py-2 text-sm transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
            >
              {t("settings.privacy.exportMarkdown")}
            </button>
          </div>
        </div>
      </SettingSection>

        </div>
      ) : null}

      {activeTab === "advanced" ? (
        <div
          role="tabpanel"
          id="settings-panel-advanced"
          aria-labelledby="settings-tab-advanced"
          className="space-y-8"
        >
      <SettingSection icon={Wrench} title={t("settings.tabs.advanced")}>
        <div className="flex flex-col gap-4 border-b border-(--border) pb-4">
          <Toggle
            checked={settings.diagnosticLogging ?? false}
            onChange={(v) =>
              void (async () => {
                setBusy(true);
                try {
                  await invoke("set_app_settings", {
                    value: { ...settings, diagnosticLogging: v },
                  });
                  setSettings({ ...settings, diagnosticLogging: v });
                  showToast(t("settings.toast.diagnosticLoggingSaved"), "success");
                } catch (e) {
                  showToast(e instanceof Error ? e.message : String(e), "error");
                } finally {
                  setBusy(false);
                }
              })()
            }
            disabled={busy || !isTauri()}
            label={t("settings.diagnosticLogging.title")}
            description={t("settings.diagnosticLogging.description")}
          />
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy || !isTauri()}
              onClick={() =>
                void invoke("open_diagnostic_log").catch((e) =>
                  showToast(e instanceof Error ? e.message : String(e), "error"),
                )
              }
              className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
            >
              {t("settings.diagnosticLogging.openLogFile")}
            </button>
            <button
              type="button"
              disabled={busy || !isTauri()}
              onClick={() =>
                void invoke("open_devtools").catch((e) =>
                  showToast(e instanceof Error ? e.message : String(e), "error"),
                )
              }
              className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2) disabled:opacity-50"
            >
              {t("settings.diagnosticLogging.openDevtools")}
            </button>
          </div>
        </div>
        <div className="flex flex-col gap-3">
          <Link
            href="/report-bug/"
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
          >
            <Bug className="size-4 text-(--accent)" aria-hidden />
            {t("nav.reportBug")}
          </Link>
          <Link
            href="/logs/"
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
          >
            <ScrollText className="size-4 text-(--accent)" aria-hidden />
            {t("nav.logs")}
          </Link>
          <Link
            href="/ioc-refresh/"
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-150 hover:bg-(--surface-2)"
          >
            <Radar className="size-4 text-(--accent)" aria-hidden />
            {t("nav.iocRefresh")}
          </Link>
          <div className="border-t border-(--border) pt-4">
            <p className="text-xs font-medium text-(--muted)">
              {t("settings.about.gitCommit")} · {t("settings.about.buildDate")} ·{" "}
              {t("settings.about.target")}
            </p>
            <p className="mt-2 break-all font-mono text-xs text-(--foreground)">
              {appMeta.gitCommit} · {formatAboutBuildDate(appMeta.buildDate, lang)} ·{" "}
              {appMeta.target}
            </p>
            <motion.button
              type="button"
              onClick={() => void copyAboutDiagnostics()}
              whileTap={{ scale: 0.98 }}
              className="mt-3 inline-flex items-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm transition-colors duration-150 hover:bg-(--surface-2)"
            >
              <Copy className="size-4 text-(--accent)" aria-hidden />
              {t("settings.about.copyDiagnostics")}
            </motion.button>
          </div>
        </div>
      </SettingSection>

        </div>
      ) : null}


      <AnimatePresence>
        {langPickerOpen ? (
          <motion.div
            className="fixed inset-0 z-60 flex items-center justify-center bg-black/60 p-4"
            role="presentation"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setLangPickerOpen(false)}
            onKeyDown={(e) => e.key === "Escape" && setLangPickerOpen(false)}
          >
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-labelledby="settings-lang-title"
              className="max-h-[90vh] w-full max-w-4xl overflow-hidden rounded-xl border border-(--border) bg-(--surface)/70 p-6 shadow-2xl backdrop-blur-md"
              initial={{ scale: 0.96, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.96, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="mb-4 flex items-start justify-between gap-3">
                <h2
                  id="settings-lang-title"
                  className="text-lg font-semibold text-(--foreground)"
                >
                  {t("settings.language.title")}
                </h2>
                <button
                  type="button"
                  onClick={() => setLangPickerOpen(false)}
                  className="rounded-lg p-2 text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground)"
                  aria-label={t("common.close")}
                >
                  <X className="size-5" aria-hidden />
                </button>
              </div>
              <div className="space-y-4">
                <LanguagePicker
                  selected={lang}
                  onSelect={(code) => void applyLanguage(code)}
                  searchPlaceholder={t("settings.language.search")}
                />
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {termsModalOpen ? (
          <motion.div
            className="fixed inset-0 z-60 flex items-center justify-center bg-black/60 p-4"
            role="presentation"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setTermsModalOpen(false)}
            onKeyDown={(e) => e.key === "Escape" && setTermsModalOpen(false)}
          >
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-labelledby="settings-terms-title"
              className="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-(--border) bg-(--surface)/70 shadow-2xl backdrop-blur-md"
              initial={{ scale: 0.96, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.96, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex shrink-0 items-center justify-between gap-3 border-b border-(--border) px-6 py-4">
                <h2
                  id="settings-terms-title"
                  className="text-lg font-semibold text-(--foreground)"
                >
                  {t("settings.legal.modalTitle")}
                </h2>
                <button
                  type="button"
                  onClick={() => setTermsModalOpen(false)}
                  className="rounded-lg p-2 text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground)"
                  aria-label={t("settings.legal.close")}
                >
                  <X className="size-5" aria-hidden />
                </button>
              </div>
              <div
                dir={isRtlLang(lang) ? "rtl" : "ltr"}
                className="max-h-[80vh] min-h-0 overflow-y-auto px-6 py-5 text-sm leading-relaxed text-(--muted)"
              >
                {translate("termsBody", lang)
                  .split("\n\n")
                  .map((para, idx) => (
                    <p key={idx} className={idx > 0 ? "mt-4" : undefined}>
                      {para}
                    </p>
                  ))}
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
