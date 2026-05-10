"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import { ScoreGauge } from "@/components/ScoreGauge";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import type { AbuseChSourceStatus, Finding, MbLookupResult } from "@/lib/types";
import { severityTier, tierColorVar } from "@/lib/thresholds";
import { ProcessActionModal } from "./ProcessActionModal";

type ProcessDrawerProps = {
  selected: Finding;
  warnAt: number;
  alertAt: number;
  onClose: () => void;
  onProcessesChanged: () => void;
};

export function ProcessDrawer({
  selected,
  warnAt,
  alertAt,
  onClose,
  onProcessesChanged,
}: ProcessDrawerProps) {
  const { t } = useLang();
  const { showToast } = useToast();
  const tier = severityTier(selected.score, warnAt, alertAt);
  const accent = tierColorVar(tier);
  const [dangerModal, setDangerModal] = useState<null | "kill" | "quarantine">(
    null,
  );
  const [mbLookupEnabled, setMbLookupEnabled] = useState(false);
  const [mbBusy, setMbBusy] = useState(false);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void invoke<AbuseChSourceStatus[]>("list_abusech_sources")
      .then((rows) => {
        if (cancelled) return;
        const mb = rows.find((r) => r.slug === "malwarebazaar");
        setMbLookupEnabled(mb?.enabled ?? false);
      })
      .catch(() => {
        if (!cancelled) setMbLookupEnabled(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const runMalwarebazaarLookup = useCallback(async () => {
    if (!selected.exePath || !isTauri()) return;
    setMbBusy(true);
    try {
      const hex = await invoke<string>("file_sha256_hex", {
        path: selected.exePath,
      });
      const res = await invoke<MbLookupResult | null>("lookup_hash_malwarebazaar", {
        sha256: hex,
      });
      if (res == null) {
        showToast(t("abusech.lookupNoResult"), "info");
        return;
      }
      const sig = res.signature?.trim() || "—";
      const tags =
        res.tags && res.tags.length > 0 ? res.tags.join(", ") : "—";
      showToast(
        t("abusech.lookupResult").replace("{signature}", sig).replace("{tags}", tags),
        "info",
      );
    } catch {
      showToast(t("abusech.lookupNoResult"), "info");
    } finally {
      setMbBusy(false);
    }
  }, [selected.exePath, showToast, t]);

  const showMbLink =
    mbLookupEnabled &&
    selected.exePath &&
    selected.authenticodeSigned === false;

  return (
    <>
    <motion.div
      className="fixed inset-0 z-40 flex justify-end bg-black/55 p-3 sm:p-6"
      role="presentation"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.2 }}
      onClick={onClose}
      onKeyDown={(e) => e.key === "Escape" && onClose()}
    >
      <motion.aside
        className="flex h-full w-full max-w-md flex-col overflow-hidden rounded-xl border border-(--border) bg-(--surface)/75 shadow-2xl backdrop-blur-md"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-title"
        initial={{ x: "105%" }}
        animate={{ x: 0 }}
        exit={{ x: "105%" }}
        transition={{ type: "spring", stiffness: 380, damping: 36 }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between border-b border-(--border) px-5 py-4">
          <div className="min-w-0">
            <div id="finding-title" className="truncate font-semibold">
              {selected.name}
            </div>
            <div className="mt-1 font-mono text-xs text-(--muted)">
              PID {selected.pid}
            </div>
          </div>
          <button
            type="button"
            className="rounded-md px-2 py-1 text-sm text-(--muted) transition-colors duration-200 hover:bg-(--surface-2) hover:text-(--foreground)"
            onClick={onClose}
          >
            {t("common.close")}
          </button>
        </div>
        <div className="flex items-center gap-4 border-b border-(--border) px-5 py-4">
          <ScoreGauge
            score={selected.score}
            warnThreshold={warnAt}
            alertThreshold={alertAt}
            size="md"
          />
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-(--muted)">
              {t("processes.detailSeverity")}
            </div>
            <div className="text-sm font-medium capitalize" style={{ color: accent }}>
              {tier}
            </div>
          </div>
        </div>
        {selected.exePath ? (
          <p className="border-b border-(--border) px-5 py-3 font-mono text-xs leading-relaxed text-(--muted)">
            {selected.exePath}
          </p>
        ) : null}
        {showMbLink ? (
          <div className="border-b border-(--border) px-5 py-3">
            <button
              type="button"
              disabled={mbBusy || !isTauri()}
              onClick={() => void runMalwarebazaarLookup()}
              className="text-xs font-medium text-(--accent-2) underline-offset-2 hover:underline disabled:opacity-50"
            >
              {mbBusy ? t("common.loading") : t("abusech.lookupHash")}
            </button>
          </div>
        ) : null}
        <div className="flex-1 overflow-auto px-5 py-4">
          <div className="text-xs font-medium uppercase tracking-wide text-(--muted)">
            {t("processes.detailReasons")}
          </div>
          <ul className="mt-3 space-y-2 text-sm text-(--foreground)">
            {selected.reasons.map((r) => (
              <li
                key={r}
                className="rounded-lg border border-(--border) bg-(--background)/50 px-3 py-2 leading-relaxed"
              >
                {r}
              </li>
            ))}
          </ul>
        </div>
        <div className="border-t border-(--border) px-5 py-4">
          <div className="text-xs font-medium uppercase tracking-wide text-(--muted)">
            {t("processes.dangerZone")}
          </div>
          <p className="mt-2 text-xs leading-relaxed text-(--muted)">
            {t("processes.dangerZoneHint")}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setDangerModal("kill")}
              className="rounded-lg border border-(--severity-high)/60 bg-(--severity-high)/15 px-3 py-1.5 text-xs font-medium text-(--foreground) transition-colors duration-200 hover:bg-(--severity-high)/25"
            >
              {t("processes.endProcess")}
            </button>
            <button
              type="button"
              onClick={() => setDangerModal("quarantine")}
              className="rounded-lg border border-(--severity-warn)/60 bg-(--severity-warn)/15 px-3 py-1.5 text-xs font-medium text-(--foreground) transition-colors duration-200 hover:bg-(--severity-warn)/25"
            >
              {t("processes.quarantine")}
            </button>
          </div>
        </div>
      </motion.aside>
    </motion.div>
    <ProcessActionModal
      open={dangerModal !== null}
      variant={dangerModal ?? "kill"}
      pid={selected.pid}
      fallbackName={selected.name}
      onClose={() => setDangerModal(null)}
      onCompleted={() => {
        onProcessesChanged();
      }}
    />
    </>
  );
}
