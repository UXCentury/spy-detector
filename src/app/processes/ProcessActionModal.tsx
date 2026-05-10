"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useToast } from "@/components/Toast";
import {
  killConfirmPayload,
  quarantineConfirmPayload,
  sha256HexUtf8,
} from "@/lib/processActionToken";
import { useLang } from "@/lib/i18nContext";

type Variant = "kill" | "quarantine";

type PrepareResult = {
  exePath: string | null;
  name: string;
  canKill: boolean;
};

type Props = {
  open: boolean;
  variant: Variant;
  pid: number;
  /** Hint label shown before prepare returns (e.g. from scan row). */
  fallbackName: string;
  onClose: () => void;
  onCompleted: () => void;
};

export function ProcessActionModal({
  open,
  variant,
  pid,
  fallbackName,
  onClose,
  onCompleted,
}: Props) {
  const { t } = useLang();
  const { showToast } = useToast();
  const [step, setStep] = useState<0 | 1>(0);
  const [prep, setPrep] = useState<PrepareResult | null>(null);
  const [prepBusy, setPrepBusy] = useState(false);
  const [typedName, setTypedName] = useState("");
  const [submitBusy, setSubmitBusy] = useState(false);

  const title =
    variant === "kill"
      ? t("processAction.kill.title")
      : t("processAction.quarantine.title");

  useEffect(() => {
    if (open) return;
    void Promise.resolve().then(() => {
      setStep(0);
      setPrep(null);
      setTypedName("");
      setPrepBusy(false);
      setSubmitBusy(false);
    });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    void Promise.resolve().then(() => {
      if (cancelled) return;
      setStep(0);
      setTypedName("");
      setPrepBusy(true);
      void invoke<PrepareResult>("prepare_process_action", { pid })
        .then((r) => {
          if (!cancelled) setPrep(r);
        })
        .catch((e: unknown) => {
          if (!cancelled) {
            showToast(e instanceof Error ? e.message : String(e), "error");
            setPrep(null);
          }
        })
        .finally(() => {
          if (!cancelled) setPrepBusy(false);
        });
    });
    return () => {
      cancelled = true;
    };
  }, [open, pid, showToast]);

  const displayName = prep?.name?.trim() ? prep.name : fallbackName;

  const nameMatches =
    typedName.trim().toLowerCase() === displayName.trim().toLowerCase();

  const runAction = async () => {
    if (!prep?.canKill || !nameMatches) return;
    const exePath = prep.exePath;
    const payload =
      variant === "kill"
        ? killConfirmPayload(pid, exePath)
        : quarantineConfirmPayload(pid, exePath);
    const confirmToken = await sha256HexUtf8(payload);
    setSubmitBusy(true);
    try {
      if (variant === "kill") {
        await invoke("kill_process", { pid, confirmToken });
        showToast(
          t("processAction.killToast").replace("{name}", displayName),
          "success",
        );
      } else {
        const r = await invoke<{ quarantinePath: string }>(
          "quarantine_process",
          { pid, confirmToken },
        );
        showToast(
          t("processAction.quarantineToast")
            .replace("{name}", displayName)
            .replace("{path}", r.quarantinePath),
          "success",
        );
      }
      onCompleted();
      onClose();
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setSubmitBusy(false);
    }
  };

  const canProceedStep0 = prep?.canKill === true && !prepBusy;
  const warnIrreversible =
    variant === "kill"
      ? t("processAction.kill.body")
      : t("processAction.quarantine.body");

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
          role="presentation"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          onKeyDown={(e) => e.key === "Escape" && onClose()}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby="pam-title"
            className="max-h-[90vh] w-full max-w-lg overflow-auto rounded-xl border border-(--border) bg-(--surface) p-6 shadow-2xl"
            initial={{ scale: 0.96, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.96, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="pam-title" className="text-lg font-semibold">
              {title}
            </h2>
            <p className="mt-1 font-mono text-xs text-(--muted)">
              PID {pid}
              {prep?.exePath ? (
                <span className="mt-2 block break-all text-(--foreground)">
                  {prep.exePath}
                </span>
              ) : null}
            </p>

            {prepBusy ? (
              <p className="mt-4 text-sm text-(--muted)">
                {t("processAction.preparing")}
              </p>
            ) : prep && !prep.canKill ? (
              <p className="mt-4 text-sm text-(--severity-warn)">
                {t("processAction.cannotAct")}
              </p>
            ) : step === 0 ? (
              <div className="mt-4 space-y-4 text-sm leading-relaxed text-(--foreground)">
                <p className="rounded-lg border border-(--border) bg-(--background)/40 p-3 text-(--muted)">
                  {warnIrreversible} {t("processAction.riskSuffix")}
                </p>
                <button
                  type="button"
                  disabled={!canProceedStep0}
                  onClick={() => setStep(1)}
                  className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {t("processAction.continue")}
                </button>
              </div>
            ) : (
              <div className="mt-4 space-y-4">
                <p className="text-sm text-(--muted)">
                  {t("processAction.typeNamePrompt")}{" "}
                  <span className="font-medium text-(--foreground)">
                    {displayName}
                  </span>
                </p>
                <label className="block text-sm">
                  <span className="text-(--muted)">
                    {t("processAction.processNameLabel")}
                  </span>
                  <input
                    type="text"
                    value={typedName}
                    onChange={(e) => setTypedName(e.target.value)}
                    autoComplete="off"
                    className="mt-1 w-full rounded-lg border border-(--border) bg-(--background)/80 px-3 py-2 text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
                  />
                </label>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setStep(0)}
                    className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-200 hover:bg-(--surface-2)"
                  >
                    {t("processAction.back")}
                  </button>
                  <button
                    type="button"
                    disabled={!nameMatches || submitBusy}
                    onClick={() => void runAction()}
                    className="rounded-lg bg-(--severity-high) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {submitBusy
                      ? t("processAction.working")
                      : variant === "kill"
                        ? t("processAction.kill.confirm")
                        : t("processAction.quarantine.confirm")}
                  </button>
                </div>
              </div>
            )}

            <div className="mt-6 flex justify-end border-t border-(--border) pt-4">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg px-3 py-1.5 text-sm text-(--muted) hover:bg-(--surface-2) hover:text-(--foreground)"
              >
                {t("processAction.cancel")}
              </button>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
