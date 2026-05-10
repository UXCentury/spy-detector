"use client";

import { invoke } from "@tauri-apps/api/core";
import Link from "next/link";
import {
  Activity,
  Braces,
  Camera,
  FileSearch,
  Globe,
  Keyboard,
  ListChecks,
  Network,
  Radar,
  Repeat,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { PulseDot } from "@/components/PulseDot";
import { ProgressBar } from "@/components/ProgressBar";
import { ScoreGauge } from "@/components/ScoreGauge";
import { SeverityDonut } from "@/components/SeverityDonut";
import { Sparkline } from "@/components/Sparkline";
import { StatCard } from "@/components/StatCard";
import { Skeleton } from "@/components/Skeleton";
import { Toggle } from "@/components/Toggle";
import { useToast } from "@/components/Toast";
import { OverviewHero } from "@/components/overview/OverviewHero";
import { formatRelativeTime } from "@/lib/formatRelativeTime";
import { useMonitoringTick } from "@/lib/hooks/useMonitoringTick";
import { useScanInterval } from "@/lib/hooks/useScanInterval";
import { useLang } from "@/lib/i18nContext";
import { useScanCompleted } from "@/lib/hooks/useScanCompleted";
import type {
  AppSettings,
  Finding,
  ScanHistoryRow,
} from "@/lib/types";

type RuntimeStatus = { elevated: boolean };

type IocEntryView = {
  token: string;
  kind: string;
  source: string;
  disabled: boolean;
};

function severityCounts(
  findings: Finding[],
  warn: number,
  alert: number,
): { low: number; warn: number; high: number } {
  let low = 0;
  let warnC = 0;
  let high = 0;
  for (const f of findings) {
    if (f.ignored) continue;
    if (f.score >= alert) high += 1;
    else if (f.score >= warn) warnC += 1;
    else low += 1;
  }
  return { low, warn: warnC, high };
}

type ComponentHealthStatus = "active" | "inactive" | "degraded" | "checking";

function healthPillClass(s: ComponentHealthStatus): string {
  switch (s) {
    case "active":
      return "border border-(--severity-low)/30 bg-(--severity-low)/12 text-(--severity-low)";
    case "degraded":
      return "border border-(--severity-warn)/35 bg-(--severity-warn)/12 text-(--severity-warn)";
    case "inactive":
      return "border border-(--severity-high)/35 bg-(--severity-high)/12 text-(--severity-high)";
    default:
      return "border border-(--border) bg-(--surface-2)/60 text-(--muted)";
  }
}

function healthPulseVar(s: ComponentHealthStatus): string {
  switch (s) {
    case "active":
      return "var(--severity-low)";
    case "degraded":
      return "var(--severity-warn)";
    case "inactive":
      return "var(--severity-high)";
    default:
      return "var(--muted)";
  }
}

function DetectionComponentRow({
  icon: Icon,
  title,
  description,
  subtext,
  hint,
  status,
  statusLabel,
  toggleSlot,
  showRestart,
  restartBusy,
  onRestart,
  restartLabel,
  restartingLabel,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  subtext?: string | null;
  hint?: string | null;
  status: ComponentHealthStatus;
  statusLabel: string;
  toggleSlot?: ReactNode;
  showRestart?: boolean;
  restartBusy?: boolean;
  onRestart?: () => void;
  restartLabel: string;
  restartingLabel: string;
}) {
  return (
    <div className="flex gap-4 py-4 first:pt-0 last:pb-0">
      <div
        className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-(--surface-2)/80 text-(--muted)"
        aria-hidden
      >
        <Icon className="size-5" />
      </div>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <span className="font-medium text-(--foreground)">{title}</span>
          <div className="flex shrink-0 items-center gap-2">
            {toggleSlot}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${healthPillClass(status)}`}
            >
              <PulseDot color={healthPulseVar(status)} className="size-1.5" />
              {statusLabel}
            </span>
          </div>
        </div>
        <p className="text-sm text-(--muted)">{description}</p>
        {subtext ? (
          <p className="text-xs text-(--muted)">{subtext}</p>
        ) : null}
        {hint ? <p className="text-xs text-(--muted)">{hint}</p> : null}
        {showRestart ? (
          <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
            <button
              type="button"
              disabled={restartBusy}
              onClick={() => onRestart?.()}
              className="rounded-lg border border-(--severity-warn)/45 bg-(--surface-2)/80 px-3 py-1.5 text-xs font-medium transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2) disabled:cursor-not-allowed disabled:opacity-60"
            >
              {restartBusy ? restartingLabel : restartLabel}
            </button>
            {restartBusy ? (
              <ProgressBar className="min-w-[120px] max-w-xs flex-1 sm:max-w-[200px]" />
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function OverviewDashboard() {
  const { t } = useLang();
  const { showToast } = useToast();
  const { tick } = useMonitoringTick();
  const { seconds: scanIntervalSeconds } = useScanInterval();
  const [elevRestartBusy, setElevRestartBusy] = useState(false);
  const [boot, setBoot] = useState(true);
  const [elevated, setElevated] = useState<boolean | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [iocCount, setIocCount] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [history, setHistory] = useState<ScanHistoryRow[]>([]);
  const [scanBusy, setScanBusy] = useState(false);
  const [iocBusy, setIocBusy] = useState(false);
  const [scanCompletedAtIso, setScanCompletedAtIso] = useState<string | null>(
    null,
  );
  const [scanCompletedBadge, setScanCompletedBadge] = useState<string | null>(
    null,
  );

  const refetchFindingsAndHistory = useCallback(async () => {
    try {
      const [latest, hist] = await Promise.all([
        invoke<Finding[] | null>("get_latest_findings"),
        invoke<ScanHistoryRow[]>("get_scan_history", { limit: 32 }),
      ]);
      setFindings(latest ?? []);
      setHistory(hist);
    } catch {
      /* ignore */
    }
  }, []);

  useScanCompleted((e) => {
    setScanCompletedAtIso(e.payload.at);
    void refetchFindingsAndHistory();
  });

  const load = useCallback(async () => {
    try {
      const [rt, s, iocRows, latest, hist] = await Promise.all([
        invoke<RuntimeStatus>("get_runtime_status"),
        invoke<AppSettings>("get_app_settings"),
        invoke<IocEntryView[]>("list_ioc_entries"),
        invoke<Finding[] | null>("get_latest_findings"),
        invoke<ScanHistoryRow[]>("get_scan_history", { limit: 32 }),
      ]);
      setElevated(rt.elevated);
      setSettings(s);
      setIocCount(iocRows.length);
      setFindings(latest ?? []);
      setHistory(hist);
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBoot(false);
    }
  }, [showToast]);

  useEffect(() => {
    void Promise.resolve().then(() => void load());
  }, [load]);

  useEffect(() => {
    void Promise.resolve().then(() => {
      if (!scanCompletedAtIso) {
        setScanCompletedBadge(null);
        return;
      }
      const age = Date.now() - new Date(scanCompletedAtIso).getTime();
      if (Number.isNaN(age) || age > 5 * 60 * 1000) {
        setScanCompletedBadge(null);
        return;
      }
      setScanCompletedBadge(formatRelativeTime(scanCompletedAtIso));
    });
  }, [scanCompletedAtIso, tick?.at]);

  const restartElevated = useCallback(async () => {
    setElevRestartBusy(true);
    try {
      await invoke("request_elevation_restart");
    } catch (e) {
      setElevRestartBusy(false);
      showToast(
        `${t("elevation.errorPrefix")} ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }, [showToast, t]);

  const warnAt = settings?.warnThreshold ?? 50;
  const alertAt = settings?.alertThreshold ?? 75;

  const persistSettingsPatch = useCallback(
    async (patch: Partial<AppSettings>) => {
      if (!settings) return;
      const prev = settings;
      const next = { ...prev, ...patch };
      setSettings(next);
      try {
        await invoke("set_app_settings", { value: next });
      } catch (e) {
        setSettings(prev);
        showToast(e instanceof Error ? e.message : String(e), "error");
      }
    },
    [settings, showToast],
  );

  const findingsForRisk = useMemo(
    () => findings.filter((f) => !f.ignored),
    [findings],
  );

  const highSeverityCount = useMemo(
    () => findingsForRisk.filter((f) => f.score >= alertAt).length,
    [findingsForRisk, alertAt],
  );

  const donutCounts = useMemo(
    () => severityCounts(findings, warnAt, alertAt),
    [findings, warnAt, alertAt],
  );

  const sparkData = useMemo(
    () => [...history].reverse().map((h) => h.maxScore),
    [history],
  );

  const historyLastScanAt = history[0]?.at ?? null;
  const lastScanRelative = formatRelativeTime(
    tick?.lastScanAt ?? historyLastScanAt,
  );

  const heroElevated = tick?.elevated ?? elevated;

  const scanMinutesLabel =
    scanIntervalSeconds == null
      ? "…"
      : String(Math.max(1, Math.round(scanIntervalSeconds / 60)));

  const healthStatusLabel = useCallback(
    (s: ComponentHealthStatus) => {
      if (s === "checking") return t("common.checking");
      if (s === "active") return t("overview.components.statusActive");
      if (s === "inactive") return t("overview.components.statusInactive");
      return t("overview.components.statusDegraded");
    },
    [t],
  );

  const processEtwEnabled = settings?.processEtwEnabled ?? true;
  const win32kEtwEnabled = settings?.win32kEtwEnabled ?? true;
  const dnsEtwEnabled = settings?.dnsEtwEnabled ?? true;
  const cameraMonitorEnabled = settings?.cameraMonitorEnabled ?? true;
  const periodicScanEnabled = settings?.periodicScanEnabled ?? true;
  const amsiEnabled = settings?.amsiEnabled ?? true;
  const yaraEnabled = settings?.yaraEnabled ?? true;

  let processEtwHealthBase: ComponentHealthStatus;
  if (!tick) processEtwHealthBase = "checking";
  else if (!tick.etwProcessActive) processEtwHealthBase = "inactive";
  // Elevated but provider off → inactive; live ETW without elevation lacks kernel image-load, etc.
  else if (!tick.elevated) processEtwHealthBase = "degraded";
  else processEtwHealthBase = "active";
  const processEtwHealth: ComponentHealthStatus = processEtwEnabled
    ? processEtwHealthBase
    : "inactive";

  let win32kHealthBase: ComponentHealthStatus;
  if (!tick) win32kHealthBase = "checking";
  else win32kHealthBase = tick.etwWin32kActive ? "active" : "inactive";
  const win32kHealth: ComponentHealthStatus = win32kEtwEnabled
    ? win32kHealthBase
    : "inactive";

  let dnsEtwHealthBase: ComponentHealthStatus;
  if (!tick) dnsEtwHealthBase = "checking";
  else dnsEtwHealthBase = tick.dnsEtwActive ? "active" : "inactive";
  const dnsEtwHealth: ComponentHealthStatus = dnsEtwEnabled
    ? dnsEtwHealthBase
    : "inactive";

  let cameraHealthBase: ComponentHealthStatus;
  if (!tick) cameraHealthBase = "checking";
  else cameraHealthBase = tick.cameraMonitorActive ? "active" : "inactive";
  const cameraHealth: ComponentHealthStatus = cameraMonitorEnabled
    ? cameraHealthBase
    : "inactive";

  const scannerHealth: ComponentHealthStatus = periodicScanEnabled
    ? "active"
    : "inactive";

  let privilegeHealth: ComponentHealthStatus;
  if (heroElevated === null) privilegeHealth = "checking";
  else privilegeHealth = heroElevated ? "active" : "degraded";

  const PrivilegeIcon =
    heroElevated === true ? ShieldCheck : ShieldAlert;

  const scannerDescription = t("overview.components.scanner.description").replace(
    "{minutes}",
    scanMinutesLabel,
  );
  const lastScanSubtext = t("overview.components.lastScan").replace(
    "{relative}",
    formatRelativeTime(tick?.lastScanAt),
  );

  const processEtwHint = !processEtwEnabled
    ? null
    : processEtwHealthBase === "inactive"
      ? t("overview.components.processEtw.hintInactive")
      : processEtwHealthBase === "degraded"
        ? t("overview.components.processEtw.hintDegraded")
        : null;

  const win32kHint =
    win32kEtwEnabled && win32kHealthBase === "inactive"
      ? t("overview.components.win32kEtw.hintInactive")
      : null;

  const dnsEtwHint =
    dnsEtwEnabled && dnsEtwHealthBase === "inactive"
      ? t("overview.components.dnsEtw.hintInactive")
      : null;

  const dnsEtwSubtext =
    dnsEtwEnabled &&
    dnsEtwHealthBase === "active" &&
    tick != null
      ? t("overview.components.dnsEtw.cachedCount").replace(
          "{count}",
          String(tick.dnsCacheSize),
        )
      : null;

  let amsiHealthBase: ComponentHealthStatus;
  if (!tick) amsiHealthBase = "checking";
  else amsiHealthBase = tick.amsiActive ? "active" : "inactive";
  const amsiHealth: ComponentHealthStatus = amsiEnabled
    ? amsiHealthBase
    : "inactive";

  let yaraHealthBase: ComponentHealthStatus;
  if (!tick) yaraHealthBase = "checking";
  else yaraHealthBase = tick.yaraRuleCount > 0 ? "active" : "degraded";
  const yaraHealth: ComponentHealthStatus = yaraEnabled
    ? yaraHealthBase
    : "inactive";

  const amsiHint =
    amsiEnabled && amsiHealthBase === "inactive"
      ? t("overview.components.amsi.hintInactive")
      : null;

  const amsiSubtext =
    tick != null && tick.amsiDetectionCount > 0
      ? t("overview.components.amsi.detectionsCount").replace(
          "{count}",
          String(tick.amsiDetectionCount),
        )
      : null;

  const yaraSubtext =
    tick != null
      ? `${t("overview.components.yara.ruleCount").replace("{count}", String(tick.yaraRuleCount))} — ${t("overview.components.yara.setsLoaded").replace("{count}", String(tick.yaraSourceSets))}`
      : null;

  let abuseChHealth: ComponentHealthStatus;
  if (!tick) abuseChHealth = "checking";
  else {
    const n =
      (tick.abusechThreatfoxCount ?? 0) + (tick.abusechUrlhausCount ?? 0);
    abuseChHealth = n > 0 ? "active" : "inactive";
  }

  const abuseChSubtext =
    tick != null
      ? t("overview.components.abuseCh.counts")
          .replace("{tf}", String(tick.abusechThreatfoxCount ?? 0))
          .replace("{uh}", String(tick.abusechUrlhausCount ?? 0))
      : null;

  const abuseChHint =
    abuseChHealth === "inactive" && tick != null
      ? t("overview.components.abuseCh.hintInactive")
      : null;

  const cameraHint =
    cameraMonitorEnabled && cameraHealthBase === "inactive"
      ? t("overview.components.camera.hintInactive")
      : null;

  const showProcessEtwRestart =
    heroElevated === false &&
    processEtwEnabled &&
    (processEtwHealthBase === "inactive" ||
      processEtwHealthBase === "degraded");
  const showWin32kRestart =
    heroElevated === false &&
    win32kEtwEnabled &&
    win32kHealthBase === "inactive";
  const showCameraRestart =
    heroElevated === false &&
    cameraMonitorEnabled &&
    cameraHealthBase === "inactive";
  const showPrivilegeRestart = heroElevated === false;

  const recent = useMemo(() => findingsForRisk.slice(0, 5), [findingsForRisk]);

  const runScan = async () => {
    setScanBusy(true);
    try {
      const next = await invoke<Finding[]>("run_scan");
      setFindings(next);
      const hist = await invoke<ScanHistoryRow[]>("get_scan_history", {
        limit: 32,
      });
      setHistory(hist);
      setScanCompletedAtIso(new Date().toISOString());
      showToast(t("overview.scanFinishedToast"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setScanBusy(false);
    }
  };

  const runIoc = async () => {
    setIocBusy(true);
    try {
      const r = await invoke<{
        success: boolean;
        message: string;
        entriesLoaded: number;
      }>("refresh_ioc");
      if (r.success) {
        showToast(r.message, "success");
        const rows = await invoke<IocEntryView[]>("list_ioc_entries");
        setIocCount(rows.length);
        const s = await invoke<AppSettings>("get_app_settings");
        setSettings(s);
      } else {
        showToast(r.message, "error");
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setIocBusy(false);
    }
  };

  if (boot || !settings) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-40 w-full rounded-2xl" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-28 w-full rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-72 w-full rounded-xl" />
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-56 w-full rounded-xl" />
          <Skeleton className="h-56 w-full rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <h1 className="sr-only">{t("overview.title")}</h1>
      <OverviewHero
        elevated={heroElevated}
        highSeverityCount={highSeverityCount}
        lastScanRelative={lastScanRelative}
        scanCompletedBadge={scanCompletedBadge}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Activity}
          label={t("overview.liveProcesses")}
          value={tick?.processCount ?? 0}
        />
        <StatCard
          icon={Network}
          label={t("overview.establishedTcp")}
          value={tick?.establishedConnections ?? 0}
        />
        <StatCard
          icon={ShieldAlert}
          label={t("overview.highSeverityFindings")}
          value={highSeverityCount}
        />
        <StatCard
          icon={ListChecks}
          label={t("overview.iocLoaded")}
          value={iocCount}
        />
      </div>

      <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-5 backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright)">
        <h3 className="text-sm font-medium text-(--muted)">
          {t("overview.components.title")}
        </h3>
        <div className="divide-y divide-(--border)">
          <DetectionComponentRow
            icon={Activity}
            title={t("overview.components.processEtw.name")}
            description={t("overview.components.processEtw.description")}
            hint={processEtwHint}
            status={processEtwHealth}
            statusLabel={healthStatusLabel(processEtwHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={processEtwEnabled}
                ariaLabel={t("overview.components.processEtw.toggleAria")}
                onChange={(v) => void persistSettingsPatch({ processEtwEnabled: v })}
              />
            }
            showRestart={showProcessEtwRestart}
            restartBusy={elevRestartBusy}
            onRestart={restartElevated}
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={Keyboard}
            title={t("overview.components.win32kEtw.name")}
            description={t("overview.components.win32kEtw.description")}
            hint={win32kHint}
            status={win32kHealth}
            statusLabel={healthStatusLabel(win32kHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={win32kEtwEnabled}
                ariaLabel={t("overview.components.win32kEtw.toggleAria")}
                onChange={(v) => void persistSettingsPatch({ win32kEtwEnabled: v })}
              />
            }
            showRestart={showWin32kRestart}
            restartBusy={elevRestartBusy}
            onRestart={restartElevated}
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={Globe}
            title={t("overview.components.dnsEtw.name")}
            description={t("overview.components.dnsEtw.description")}
            hint={dnsEtwHint}
            subtext={dnsEtwSubtext}
            status={dnsEtwHealth}
            statusLabel={healthStatusLabel(dnsEtwHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={dnsEtwEnabled}
                ariaLabel={t("overview.components.dnsEtw.toggleAria")}
                onChange={(v) => void persistSettingsPatch({ dnsEtwEnabled: v })}
              />
            }
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={Braces}
            title={t("overview.components.amsi.name")}
            description={t("overview.components.amsi.description")}
            hint={amsiHint}
            subtext={amsiSubtext}
            status={amsiHealth}
            statusLabel={healthStatusLabel(amsiHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={amsiEnabled}
                ariaLabel={t("overview.components.amsi.toggleAria")}
                onChange={(v) => void persistSettingsPatch({ amsiEnabled: v })}
              />
            }
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={FileSearch}
            title={t("overview.components.yara.name")}
            description={t("overview.components.yara.description")}
            subtext={yaraSubtext}
            status={yaraHealth}
            statusLabel={healthStatusLabel(yaraHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={yaraEnabled}
                ariaLabel={t("overview.components.yara.toggleAria")}
                onChange={(v) => void persistSettingsPatch({ yaraEnabled: v })}
              />
            }
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={Radar}
            title={t("overview.components.abuseCh.name")}
            description={t("overview.components.abuseCh.description")}
            hint={abuseChHint}
            subtext={abuseChSubtext}
            status={abuseChHealth}
            statusLabel={healthStatusLabel(abuseChHealth)}
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={Camera}
            title={t("overview.components.camera.name")}
            description={t("overview.components.camera.description")}
            hint={cameraHint}
            status={cameraHealth}
            statusLabel={healthStatusLabel(cameraHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={cameraMonitorEnabled}
                ariaLabel={t("overview.components.camera.toggleAria")}
                onChange={(v) =>
                  void persistSettingsPatch({ cameraMonitorEnabled: v })
                }
              />
            }
            showRestart={showCameraRestart}
            restartBusy={elevRestartBusy}
            onRestart={restartElevated}
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={Repeat}
            title={t("overview.components.scanner.name")}
            description={scannerDescription}
            subtext={lastScanSubtext}
            status={scannerHealth}
            statusLabel={healthStatusLabel(scannerHealth)}
            toggleSlot={
              <Toggle
                compact
                checked={periodicScanEnabled}
                ariaLabel={t("overview.components.scanner.toggleAria")}
                onChange={(v) =>
                  void persistSettingsPatch({ periodicScanEnabled: v })
                }
              />
            }
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
          <DetectionComponentRow
            icon={PrivilegeIcon}
            title={t("overview.components.privilege.name")}
            description={
              heroElevated === true
                ? t("overview.components.privilege.elevated")
                : heroElevated === false
                  ? t("overview.components.privilege.limited")
                  : t("common.checking")
            }
            status={privilegeHealth}
            statusLabel={healthStatusLabel(privilegeHealth)}
            showRestart={showPrivilegeRestart}
            restartBusy={elevRestartBusy}
            onRestart={restartElevated}
            restartLabel={t("overview.components.restartElevated")}
            restartingLabel={t("elevation.starting")}
          />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-5 backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright)">
          <h3 className="text-sm font-medium text-(--muted)">
            {t("overview.severityMix")}
          </h3>
          <div className="mt-4 flex justify-center">
            <SeverityDonut counts={donutCounts} />
          </div>
        </div>
        <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-5 backdrop-blur-md transition-colors duration-200 hover:border-(--border-bright)">
          <h3 className="text-sm font-medium text-(--muted)">
            {t("overview.scanHistory")}
          </h3>
          <div className="mt-6 flex min-h-[140px] items-center justify-center">
            <Sparkline data={sparkData} height={120} />
          </div>
          <p className="mt-2 text-center text-xs text-(--muted)">
            {t("overview.sparklineFootnote")}
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-(--border) bg-(--surface)/70 p-5 backdrop-blur-md">
        <h3 className="text-sm font-medium text-(--muted)">
          {t("overview.quickActionsTitle")}
        </h3>
        <div className="mt-4 flex flex-wrap gap-3">
          <button
            type="button"
            disabled={scanBusy}
            onClick={() => void runScan()}
            className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {scanBusy ? t("overview.scanning") : t("overview.scanNow")}
          </button>
          {scanBusy ? <ProgressBar className="min-w-[140px] max-w-xs flex-1 self-center" /> : null}
          <button
            type="button"
            disabled={iocBusy}
            onClick={() => void runIoc()}
            className="rounded-lg border border-(--border) bg-(--surface-2)/80 px-4 py-2 text-sm font-medium transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2) disabled:opacity-50"
          >
            {iocBusy ? t("overview.refreshingIoc") : t("overview.refreshIoc")}
          </button>
          {iocBusy ? (
            <ProgressBar className="min-w-[120px] max-w-xs flex-1 self-center" />
          ) : null}
          <Link
            href="/alerts/"
            className="inline-flex items-center rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2)"
          >
            {t("overview.viewAlerts")}
          </Link>
          <Link
            href="/processes/"
            className="inline-flex items-center rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-200 hover:border-(--border-bright) hover:bg-(--surface-2)"
          >
            {t("overview.openProcesses")}
          </Link>
        </div>
      </div>

      <div>
        <div className="mb-3 flex items-center justify-between gap-2">
          <h3 className="text-lg font-semibold tracking-tight">
            {t("overview.recentFindings")}
          </h3>
          <Link
            href="/processes/"
            className="text-sm text-(--accent) transition-opacity hover:opacity-80"
          >
            {t("overview.allResultsLink")}
          </Link>
        </div>
        <div className="overflow-hidden rounded-xl border border-(--border) bg-(--surface)/60">
          {recent.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-(--muted)">
              {t("overview.noFindingsBody")}
            </div>
          ) : (
            <ul className="divide-y divide-(--border)">
              {recent.map((f) => (
                <li key={`${f.pid}-${f.name}`}>
                  <Link
                    href="/processes/"
                    className="flex w-full items-center gap-4 px-4 py-3 text-left transition-colors duration-200 hover:bg-(--surface-2)/50"
                  >
                    <ScoreGauge
                      score={f.score}
                      warnThreshold={warnAt}
                      alertThreshold={alertAt}
                      size="sm"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-(--foreground)">
                        {f.name}
                      </div>
                      <div className="truncate text-xs text-(--muted)">
                        {f.reasons[0] ?? t("alerts.noReason")}
                      </div>
                    </div>
                    <div className="shrink-0 font-mono text-xs tabular-nums text-(--muted)">
                      {f.score}
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
