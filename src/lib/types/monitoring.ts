export type MonitoringTick = {
  at: string;
  processCount: number;
  establishedConnections: number;
  latestAlertAt: string | null;
  etwProcessActive: boolean;
  etwWin32kActive: boolean;
  dnsEtwActive: boolean;
  dnsCacheSize: number;
  cameraMonitorActive: boolean;
  activeCameraPids: number[];
  elevated: boolean;
  scanInProgress: boolean;
  lastScanAt: string | null;
  lastScanMaxScore: number | null;
  recentLaunches5m: number;
  remoteThreadEvents5m: number;
  yaraRuleCount: number;
  amsiActive: boolean;
  amsiDetectionCount: number;
  yaraSourceSets: number;
  abusechThreatfoxCount: number;
  abusechUrlhausCount: number;
};

export type ScanCompletedEvent = {
  at: string;
  findingsCount: number;
  maxScore: number;
};
