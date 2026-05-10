export type Finding = {
  pid: number;
  name: string;
  exePath: string | null;
  score: number;
  reasons: string[];
  suspiciousImageLoads?: number;
  ignored?: boolean;
  authenticodeSigned?: boolean | null;
};

export type ProcessRow = {
  pid: number;
  name: string;
  exePath: string | null;
  ignored: boolean;
};

export type AllowlistEntry = {
  imagePath: string;
  name: string;
  createdAt: string;
  reason: string | null;
};

export type AppSettings = {
  warnThreshold: number;
  alertThreshold: number;
  disabledSignatureTokens: string[];
  iocLastRefreshedAt?: string | null;
  amsiEnabled?: boolean;
  yaraEnabled?: boolean;
  autoScanOnLaunch?: boolean;
  trayAlertsEnabled?: boolean;
  diagnosticLogging?: boolean;
  threadInjectionScannerEnabled?: boolean;
  processEtwEnabled?: boolean;
  win32kEtwEnabled?: boolean;
  dnsEtwEnabled?: boolean;
  cameraMonitorEnabled?: boolean;
  periodicScanEnabled?: boolean;
};

export type ScanHistoryRow = {
  at: string;
  count: number;
  maxScore: number;
};

export type NetworkConnectionRow = {
  pid: number;
  processName: string;
  remoteIp: string;
  remotePort: number;
  reverseDns: string | null;
  resolvedViaDnsEtw?: boolean;
  iocMatch: boolean;
  iocSource: string | null;
  iocCategory: string | null;
  abuseChFamily?: string | null;
  abuseChTags?: string[] | null;
  beaconSuspect: boolean;
};

// dns etw additions — (ioc.yaml network UI may reference `network.flags.dnsEtw` via i18n)

export type IpFeedStatus = {
  slug: string;
  label: string;
  category: string;
  enabled: boolean;
  indicatorCount: number;
  lastRefreshedAt?: string | null;
  defaultEnabled: boolean;
  upstreamUrl: string;
};

export type IpFeedRefreshRow = {
  slug: string;
  status: string;
  indicatorCount: number;
  message?: string | null;
};

export type IpFeedsRefreshSummary = {
  ok: boolean;
  feeds: IpFeedRefreshRow[];
};

export type EventLogRow = {
  id: number;
  ts: string;
  kind: string;
  severity: string;
  pid?: number | null;
  processName?: string | null;
  imagePath?: string | null;
  summary: string;
  details?: Record<string, unknown> | null;
};

// browser history + dev infra additions
export type HistoryFinding = {
  id: number;
  browser: string;
  profile: string;
  url: string;
  host: string;
  title: string | null;
  lastVisitAt: string;
  matchedCategories: string[];
  sourceLabel: string | null;
  severity: "info" | "low" | "warn" | "high";
  score: number;
};

export type BrowserHistoryScanResult = {
  scannedAt: string;
  browsersScanned: string[];
  totalFindings: number;
  urlsScanned: number;
  byCategory: Record<string, number>;
};

export type BrowserHistoryDeleteOutcome = {
  url: string;
  browser: string;
  success: boolean;
  error: string | null;
  notPresent?: boolean;
};

export type BrowserHistoryDeleteSummary = {
  attempted: number;
  succeeded: number;
  failed: number;
  lockedBrowsers: string[];
  outcomes: BrowserHistoryDeleteOutcome[];
  runningBrowsers?: string[];
};

export type CloseBrowserResult = {
  browser: string;
  closedPids: number[];
  remainingPids: number[];
  forced: boolean;
  error: string | null;
};

export type PreflightSummary = {
  findingCount: number;
  affectedBrowsers: string[];
  runningBrowsers: string[];
};

export type AbuseChSourceStatus = {
  slug: string;
  label: string;
  enabled: boolean;
  indicatorCount: number;
  lastRefreshedAt?: string | null;
  defaultEnabled: boolean;
  upstreamUrl: string;
};

export type AbuseChRefreshRow = {
  slug: string;
  status: string;
  indicatorCount: number;
  message?: string | null;
};

export type AbuseChRefreshSummary = {
  ok: boolean;
  feeds: AbuseChRefreshRow[];
};

export type MbLookupResult = {
  signature?: string | null;
  tags: string[];
  firstSeen?: string | null;
};

export type StartupEntry = {
  id: string;
  name: string;
  command: string;
  imagePath: string | null;
  source:
    | "hkcu-run"
    | "hkcu-run-once"
    | "hklm-run"
    | "hklm-run-once"
    | "hklm-wow64-run"
    | "startup-folder-user"
    | "startup-folder-all-users"
    | "task-scheduler";
  scope: "current-user" | "all-users" | "system";
  firstSeen: string;
  lastModified: string | null;
  signed: boolean | null;
  publisher: string | null;
  iocMatch: string | null;
  enabled: boolean;
  score: number;
  severity: "info" | "low" | "warn" | "high";
  reasons: string[];
  canDisable: boolean;
  note: string | null;
};

export type ServiceEntry = {
  name: string;
  displayName: string;
  description: string | null;
  status: string;
  startType: string;
  binaryPath: string | null;
  account: string | null;
  signed: boolean | null;
  publisher: string | null;
  iocMatch: string | null;
  score: number;
  severity: "info" | "low" | "warn" | "high";
  reasons: string[];
  canDisable: boolean;
  isMicrosoft: boolean;
  isCritical: boolean;
  note: string | null;
};
