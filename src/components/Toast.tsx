"use client";

import {
  AlertTriangle,
  Ban,
  Camera,
  Mic,
  ScanSearch,
  Shield,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import {
  createContext,
  useCallback,
  useContext,
  useId,
  useState,
  type ReactNode,
} from "react";
import { AnimatePresence, motion } from "framer-motion";

import type {
  NotificationIcon,
  NotificationSeverity,
} from "@/components/notifications/NotificationCenter";

type Tone = "success" | "error" | "info";

type ToastItemSimple = { kind: "simple"; id: string; message: string; tone: Tone };

export type RichToastInput = {
  severity: NotificationSeverity;
  icon: NotificationIcon;
  title: string;
  body?: string;
  href?: string;
  onView?: () => void;
  viewLabel?: string;
};

type ToastItemRich = { kind: "rich"; id: string } & RichToastInput;

type ToastItem = ToastItemSimple | ToastItemRich;

type ToastContextValue = {
  showToast: (message: string, tone?: Tone) => void;
  showNotificationToast: (opts: RichToastInput) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const toneStyles: Record<Tone, string> = {
  success:
    "border-(--severity-low)/40 bg-(--surface)/95 text-(--foreground)",
  error:
    "border-(--severity-high)/45 bg-(--surface)/95 text-(--foreground)",
  info: "border-(--border-bright)/50 bg-(--surface)/95 text-(--foreground)",
};

const severityBar: Record<NotificationSeverity, string> = {
  info: "bg-(--severity-low)",
  low: "bg-(--severity-low)",
  warn: "bg-(--severity-warn)",
  high: "bg-(--severity-high)",
};

const iconMap: Record<NotificationIcon, LucideIcon> = {
  alert: AlertTriangle,
  shield: Shield,
  camera: Camera,
  mic: Mic,
  thread: Waypoints,
  scan: ScanSearch,
  kill: Ban,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const baseId = useId();

  const showToast = useCallback((message: string, tone: Tone = "info") => {
    const id = `${baseId}-${Date.now()}`;
    const item: ToastItemSimple = { kind: "simple", id, message, tone };
    setItems((p) => [...p, item]);
    window.setTimeout(() => {
      setItems((p) => p.filter((t) => t.id !== id));
    }, 4200);
  }, [baseId]);

  const showNotificationToast = useCallback(
    (opts: RichToastInput) => {
      const id = `${baseId}-rich-${Date.now()}`;
      const item: ToastItemRich = { kind: "rich", id, ...opts };
      setItems((p) => [...p, item]);
      window.setTimeout(() => {
        setItems((p) => p.filter((t) => t.id !== id));
      }, 5200);
    },
    [baseId],
  );

  return (
    <ToastContext.Provider value={{ showToast, showNotificationToast }}>
      {children}
      <div
        className="pointer-events-none fixed bottom-6 right-6 z-200 flex max-w-sm flex-col gap-2"
        aria-live="polite"
      >
        <AnimatePresence mode="popLayout">
          {items.map((item) =>
            item.kind === "simple" ? (
              <motion.div
                key={item.id}
                layout
                initial={{ opacity: 0, y: 10, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 6, scale: 0.98 }}
                transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                className={`pointer-events-auto rounded-lg border px-4 py-3 text-sm shadow-lg backdrop-blur-md ${toneStyles[item.tone]}`}
              >
                {item.message}
              </motion.div>
            ) : (
              <motion.div
                key={item.id}
                layout
                initial={{ opacity: 0, y: 12, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.98 }}
                transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                className="pointer-events-auto flex max-w-sm overflow-hidden rounded-lg border border-(--border-bright)/45 bg-(--surface)/95 text-sm shadow-lg backdrop-blur-md"
              >
                <div
                  className={`w-1 shrink-0 ${severityBar[item.severity]}`}
                  aria-hidden
                />
                <div className="flex min-w-0 flex-1 flex-col gap-2 px-3 py-3">
                  <div className="flex gap-2">
                    {(() => {
                      const Ico = iconMap[item.icon];
                      return (
                        <Ico
                          className="mt-0.5 size-4 shrink-0 text-(--accent)"
                          aria-hidden
                        />
                      );
                    })()}
                    <div className="min-w-0 flex-1">
                      <p className="font-semibold leading-snug text-(--foreground)">
                        {item.title}
                      </p>
                      {item.body ? (
                        <p className="mt-0.5 line-clamp-2 text-xs text-(--muted)">
                          {item.body}
                        </p>
                      ) : null}
                    </div>
                  </div>
                  {item.onView ? (
                    <div className="flex justify-end border-t border-(--border)/60 pt-2">
                      <button
                        type="button"
                        onClick={() => {
                          item.onView?.();
                          setItems((p) => p.filter((x) => x.id !== item.id));
                        }}
                        className="rounded-md px-2 py-1 text-xs font-medium text-(--accent) transition-colors hover:bg-(--surface-2)"
                      >
                        {item.viewLabel ?? "View"}
                      </button>
                    </div>
                  ) : null}
                </div>
              </motion.div>
            ),
          )}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used within ToastProvider");
  }
  return ctx;
}
