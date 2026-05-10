"use client";

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, ChevronRight, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { usePageReady } from "@/lib/PageStatus";
import { PulseDot } from "@/components/PulseDot";
import { ScoreGauge } from "@/components/ScoreGauge";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import type { AppSettings, Finding } from "@/lib/types";
import { severityTier, tierColorVar } from "@/lib/thresholds";

export type AlertPayload = {
  pid: number;
  name: string;
  score: number;
  reasons: string[];
  exePath?: string | null;
  suspiciousImageLoads?: number;
};

type AlertItem = AlertPayload & { id: string; receivedAt: number };

export default function AlertsPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [items, setItems] = useState<AlertItem[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [since] = useState(() => new Date());
  const [thresholds, setThresholds] = useState({
    warn: 50,
    alert: 75,
  });
  const idRef = useRef(0);
  const [bootReady, setBootReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const results = await Promise.allSettled([
          invoke<Finding[] | null>("get_latest_findings"),
          invoke<AppSettings>("get_app_settings"),
        ]);
        const settingsResult = results[1];
        if (
          !cancelled &&
          settingsResult.status === "fulfilled"
        ) {
          const s = settingsResult.value;
          setThresholds({ warn: s.warnThreshold, alert: s.alertThreshold });
        }
      } finally {
        if (!cancelled) setBootReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  usePageReady(bootReady);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    void listen<AlertPayload>("alert", (e) => {
      const id = `a-${Date.now()}-${(idRef.current += 1)}`;
      setItems((prev) =>
        [{ ...e.payload, id, receivedAt: Date.now() }, ...prev].slice(0, 200),
      );
    }).then((u) => {
      unlisten = u;
    });
    return () => {
      void unlisten?.();
    };
  }, []);

  const clearAll = () => {
    setItems([]);
    showToast(t("alerts.clearedToast"), "info");
  };

  const sinceLabel = since.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("alerts.title")}</h1>
          <p className="mt-2 max-w-2xl text-sm text-(--muted)">
            {t("alerts.subtitle")}
          </p>
        </div>
        {items.length > 0 ? (
          <button
            type="button"
            onClick={clearAll}
            className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--surface)/80 px-3 py-2 text-xs font-medium transition-colors duration-200 hover:border-(--severity-high)/40 hover:bg-(--surface-2)"
          >
            <Trash2 className="size-3.5" aria-hidden />
            {t("alerts.clearAll")}
          </button>
        ) : null}
      </div>

      {items.length === 0 ? (
        <div className="rounded-xl border border-dashed border-(--border) bg-(--surface)/50 px-6 py-14 text-center">
          <div className="flex justify-center gap-2 text-sm text-(--muted)">
            <PulseDot />
            <span>
              {t("alerts.empty")} {sinceLabel}
            </span>
          </div>
          <p className="mt-3 text-xs text-(--muted)">
            {t("alerts.emptyHint")}
          </p>
        </div>
      ) : (
        <ul className="space-y-3">
          <AnimatePresence initial={false}>
            {items.map((a) => {
              const tier = severityTier(a.score, thresholds.warn, thresholds.alert);
              const bar = tierColorVar(tier);
              const open = expanded === a.id;
              return (
                <motion.li
                  key={a.id}
                  layout
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                  className="overflow-hidden rounded-xl border border-(--border) bg-(--surface)/70 shadow-sm backdrop-blur-md"
                >
                  <button
                    type="button"
                    className="flex w-full gap-0 text-left"
                    onClick={() => setExpanded(open ? null : a.id)}
                  >
                    <div
                      className="w-1.5 shrink-0 self-stretch"
                      style={{ background: bar }}
                      aria-hidden
                    />
                    <div className="flex min-w-0 flex-1 flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center">
                      <div className="flex min-w-0 flex-1 items-start gap-3">
                        <span className="mt-0.5 text-(--muted)">
                          {open ? (
                            <ChevronDown className="size-4" aria-hidden />
                          ) : (
                            <ChevronRight className="size-4" aria-hidden />
                          )}
                        </span>
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2 font-medium text-(--foreground)">
                            <span>
                              {a.name}{" "}
                              <span className="font-mono text-sm text-(--muted)">
                                ({a.pid})
                              </span>
                            </span>
                            {a.reasons.some((r) => r.includes("[Real-time]")) ? (
                              <span className="rounded-md border border-(--severity-high)/35 bg-(--severity-high)/12 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-(--foreground)">
                                {t("alerts.realtimeLabel")}
                              </span>
                            ) : null}
                          </div>
                          <div className="mt-1 line-clamp-2 text-xs text-(--muted)">
                            {a.reasons[0] ?? t("alerts.noReason")}
                          </div>
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-3 pl-7 sm:pl-0">
                        <ScoreGauge
                          score={a.score}
                          warnThreshold={thresholds.warn}
                          alertThreshold={thresholds.alert}
                          size="sm"
                        />
                        <span className="font-mono text-[10px] text-(--muted)">
                          {new Date(a.receivedAt).toLocaleTimeString(undefined, {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                          })}
                        </span>
                      </div>
                    </div>
                  </button>
                  {open ? (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="border-t border-(--border) bg-(--background)/30 px-4 py-3 pl-12"
                    >
                      <ul className="space-y-2 text-sm text-(--foreground)">
                        {a.reasons.map((r) => (
                          <li
                            key={r}
                            className="rounded-lg border border-(--border)/80 px-3 py-2 leading-relaxed"
                          >
                            {r}
                          </li>
                        ))}
                      </ul>
                    </motion.div>
                  ) : null}
                </motion.li>
              );
            })}
          </AnimatePresence>
        </ul>
      )}
    </div>
  );
}
