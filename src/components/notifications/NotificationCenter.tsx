"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";

import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import type { AppSettings } from "@/lib/types";

const STORAGE_ITEMS = "notifications:v1";
const STORAGE_LAST_READ = "notifications:lastReadAt";

const LS_IN_APP = "notif:inApp";
const LS_NATIVE = "notif:native";
const LS_CAM_MIC = "notif:cameraMic";
const LS_ACTIONS = "notif:actions";
const LS_AUTOSTART = "notif:autostart";

export type NotificationSeverity = "info" | "low" | "warn" | "high";

export type NotificationIcon =
  | "alert"
  | "shield"
  | "camera"
  | "mic"
  | "thread"
  | "scan"
  | "kill";

export type Notification = {
  id: string;
  ts: number;
  severity: NotificationSeverity;
  icon: NotificationIcon;
  title: string;
  body?: string;
  href?: string;
  read: boolean;
};

export type NotificationPushInput = Omit<Notification, "id" | "ts" | "read">;

export type NotificationPrefs = {
  inApp: boolean;
  native: boolean;
  cameraMic: boolean;
  actions: boolean;
  autostart: boolean;
};

type NotificationContextValue = {
  notifications: Notification[];
  unreadCount: number;
  push: (n: NotificationPushInput) => void;
  markAllRead: () => void;
  markRead: (id: string) => void;
  clear: () => void;
  prefs: NotificationPrefs;
  setPref: <K extends keyof NotificationPrefs>(
    key: K,
    value: NotificationPrefs[K],
  ) => void;
  popoverOpen: boolean;
  setPopoverOpen: (open: boolean) => void;
};

const NotificationContext = createContext<NotificationContextValue | null>(
  null,
);

function readBool(key: string, defaultTrue: boolean): boolean {
  if (typeof window === "undefined") return defaultTrue;
  const raw = localStorage.getItem(key);
  if (raw === null) return defaultTrue;
  return raw !== "false";
}

export function loadNotificationPrefs(): NotificationPrefs {
  return {
    inApp: readBool(LS_IN_APP, true),
    native: readBool(LS_NATIVE, true),
    cameraMic: readBool(LS_CAM_MIC, true),
    actions: readBool(LS_ACTIONS, true),
    autostart: readBool(LS_AUTOSTART, false),
  };
}

function loadStoredNotifications(): Notification[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_ITEMS);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Notification[];
    if (!Array.isArray(parsed)) return [];
    const lastRead = Number(localStorage.getItem(STORAGE_LAST_READ) ?? "0");
    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;
    return parsed
      .filter((n) => {
        if (!n || typeof n.id !== "string" || typeof n.ts !== "number")
          return false;
        if (n.read && now - n.ts > day) return false;
        return true;
      })
      .map((n) => ({
        ...n,
        read: n.read || (lastRead > 0 && n.ts <= lastRead),
      }))
      .slice(0, 50);
  } catch {
    return [];
  }
}

export function NotificationCenterProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { t } = useLang();
  const { showNotificationToast } = useToast();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [hydrated, setHydrated] = useState(false);
  const [prefs, setPrefsState] = useState<NotificationPrefs>(
    loadNotificationPrefs,
  );
  const nativeGrantedRef = useRef<boolean | null>(null);
  const prefsRef = useRef(prefs);
  useLayoutEffect(() => {
    prefsRef.current = prefs;
  }, [prefs]);
  // Master kill switch for OS-native (tray) toasts. Mirrors
  // AppSettings.trayAlertsEnabled, refreshed on mount + whenever the
  // Settings page emits `app_settings_changed`. Defaults true so that a
  // first-run user (or non-Tauri preview) never loses notifications.
  const trayAlertsEnabledRef = useRef<boolean>(true);
  const [popoverOpen, setPopoverOpen] = useState(false);
  const popoverOpenRef = useRef(false);
  useLayoutEffect(() => {
    popoverOpenRef.current = popoverOpen;
  }, [popoverOpen]);

  useEffect(() => {
    void Promise.resolve().then(() => {
      setNotifications(loadStoredNotifications());
      setPrefsState(loadNotificationPrefs());
      setHydrated(true);
    });
  }, []);

  useEffect(() => {
    if (!hydrated || typeof window === "undefined") return;
    try {
      localStorage.setItem(STORAGE_ITEMS, JSON.stringify(notifications));
    } catch {
      /* ignore */
    }
  }, [notifications, hydrated]);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void (async () => {
      try {
        let g = await isPermissionGranted();
        if (!g) g = (await requestPermission()) === "granted";
        if (!cancelled) nativeGrantedRef.current = g;
      } catch {
        if (!cancelled) nativeGrantedRef.current = false;
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Track the master tray-alerts kill switch. We deliberately use a ref
  // (read inside `push`) instead of state so flipping the toggle never
  // re-creates `push` and any consumers' callbacks downstream.
  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void (async () => {
      try {
        const s = await invoke<AppSettings>("get_app_settings");
        if (!cancelled) {
          trayAlertsEnabledRef.current = s.trayAlertsEnabled !== false;
        }
      } catch {
        if (!cancelled) trayAlertsEnabledRef.current = true;
      }
    })();
    const unlistenPromise = listen<AppSettings>(
      "app_settings_changed",
      (event) => {
        const v = event.payload?.trayAlertsEnabled;
        trayAlertsEnabledRef.current = v !== false;
      },
    );
    return () => {
      cancelled = true;
      void unlistenPromise.then((un) => un());
    };
  }, []);

  const persistLastRead = useCallback((ts: number) => {
    try {
      localStorage.setItem(STORAGE_LAST_READ, String(ts));
    } catch {
      /* ignore */
    }
  }, []);

  const setPref = useCallback(
    <K extends keyof NotificationPrefs>(key: K, value: NotificationPrefs[K]) => {
      const keys: Record<keyof NotificationPrefs, string> = {
        inApp: LS_IN_APP,
        native: LS_NATIVE,
        cameraMic: LS_CAM_MIC,
        actions: LS_ACTIONS,
        autostart: LS_AUTOSTART,
      };
      try {
        localStorage.setItem(keys[key], value ? "true" : "false");
      } catch {
        /* ignore */
      }
      setPrefsState((p) => ({ ...p, [key]: value }));
    },
    [],
  );

  const unreadCount = useMemo(
    () => notifications.filter((n) => !n.read).length,
    [notifications],
  );

  const push = useCallback(
    (input: NotificationPushInput) => {
      const id =
        typeof crypto !== "undefined" && crypto.randomUUID
          ? crypto.randomUUID()
          : `n-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
      const ts = Date.now();
      const item: Notification = { ...input, id, ts, read: false };

      const p = prefsRef.current;
      if (p.inApp) {
        setNotifications((prev) => [item, ...prev].slice(0, 50));
        if (!popoverOpenRef.current) {
          showNotificationToast({
            severity: input.severity,
            icon: input.icon,
            title: input.title,
            body: input.body,
            href: input.href,
            viewLabel: t("notifications.view"),
            onView:
              input.href != null && input.href !== ""
                ? () => router.push(input.href!)
                : undefined,
          });
        }
      }

      if (
        p.native &&
        trayAlertsEnabledRef.current &&
        nativeGrantedRef.current === true &&
        isTauri()
      ) {
        void (async () => {
          try {
            const w = WebviewWindow.getCurrent();
            const visible = await w.isVisible();
            const minimized = await w.isMinimized();
            if (visible && !minimized) return;
            const bodyRaw =
              input.body != null && input.body !== ""
                ? input.body.slice(0, 320)
                : input.title.slice(0, 320);
            await sendNotification({
              title: input.title.slice(0, 120),
              body: bodyRaw,
            });
          } catch {
            /* ignore */
          }
        })();
      }
    },
    [router, showNotificationToast, t],
  );

  const markAllRead = useCallback(() => {
    const ts = Date.now();
    persistLastRead(ts);
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, [persistLastRead]);

  const markRead = useCallback((id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n)),
    );
  }, []);

  const clear = useCallback(() => {
    setNotifications([]);
    try {
      localStorage.removeItem(STORAGE_ITEMS);
      localStorage.removeItem(STORAGE_LAST_READ);
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo(
    () => ({
      notifications,
      unreadCount,
      push,
      markAllRead,
      markRead,
      clear,
      prefs,
      setPref,
      popoverOpen,
      setPopoverOpen,
    }),
    [
      notifications,
      unreadCount,
      push,
      markAllRead,
      markRead,
      clear,
      prefs,
      setPref,
      popoverOpen,
    ],
  );

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotificationCenter(): NotificationContextValue {
  const ctx = useContext(NotificationContext);
  if (!ctx) {
    throw new Error("useNotificationCenter must be used within provider");
  }
  return ctx;
}
