let audioEl: HTMLAudioElement | null = null;
let lastPlayedAt = 0;
const MIN_INTERVAL_MS = 4000;

let cameraAudioEl: HTMLAudioElement | null = null;
let lastCameraPlayedAt = 0;
const MIN_CAMERA_INTERVAL_MS = 4000;

function readStoredEnabled(): boolean {
  if (typeof window === "undefined") return true;
  return localStorage.getItem("soundEnabled") !== "false";
}

function readStoredSub(key: string, defaultOn: boolean): boolean {
  if (typeof window === "undefined") return defaultOn;
  const raw = localStorage.getItem(key);
  if (raw === null) return defaultOn;
  return raw !== "false";
}

let soundEnabled = readStoredEnabled();
let soundOnIssue = readStoredSub("soundOnIssue", true);
let soundOnCamera = readStoredSub("soundOnCamera", true);

export function setSoundEnabled(v: boolean) {
  soundEnabled = v;
  if (typeof window !== "undefined") {
    localStorage.setItem("soundEnabled", v ? "true" : "false");
  }
}

export function isSoundEnabled(): boolean {
  return soundEnabled;
}

export function setSoundOnIssue(v: boolean) {
  soundOnIssue = v;
  if (typeof window !== "undefined") {
    localStorage.setItem("soundOnIssue", v ? "true" : "false");
  }
}

export function isSoundOnIssue(): boolean {
  return soundOnIssue;
}

export function setSoundOnCamera(v: boolean) {
  soundOnCamera = v;
  if (typeof window !== "undefined") {
    localStorage.setItem("soundOnCamera", v ? "true" : "false");
  }
}

export function isSoundOnCamera(): boolean {
  return soundOnCamera;
}

export function playIssueDetected(opts?: { volume?: number; force?: boolean }) {
  if (typeof window === "undefined") return;
  if (!soundEnabled) return;
  if (!opts?.force && !soundOnIssue) return;
  const now = Date.now();
  if (!opts?.force && now - lastPlayedAt < MIN_INTERVAL_MS) return;
  lastPlayedAt = now;
  if (!audioEl) {
    audioEl = new Audio("/sfx/issue-detected.mp3");
    audioEl.preload = "auto";
  }
  audioEl.volume = Math.max(0, Math.min(1, opts?.volume ?? 0.5));
  audioEl.currentTime = 0;
  void audioEl.play().catch(() => {});
}

export function playCameraOpened(opts?: { volume?: number; force?: boolean }) {
  if (typeof window === "undefined") return;
  if (!soundEnabled) return;
  if (!opts?.force && !soundOnCamera) return;
  const now = Date.now();
  if (!opts?.force && now - lastCameraPlayedAt < MIN_CAMERA_INTERVAL_MS) return;
  lastCameraPlayedAt = now;
  if (!cameraAudioEl) {
    cameraAudioEl = new Audio("/sfx/camera-is-open.mp3");
    cameraAudioEl.preload = "auto";
  }
  cameraAudioEl.volume = Math.max(0, Math.min(1, opts?.volume ?? 0.5));
  cameraAudioEl.currentTime = 0;
  void cameraAudioEl.play().catch(() => {});
}
