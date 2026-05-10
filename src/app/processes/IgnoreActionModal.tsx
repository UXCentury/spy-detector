"use client";

import { invoke } from "@tauri-apps/api/core";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";

type Props = {
  open: boolean;
  imagePath: string;
  processName: string;
  onClose: () => void;
  onCompleted: () => void;
};

export function IgnoreActionModal({
  open,
  imagePath,
  processName,
  onClose,
  onCompleted,
}: Props) {
  const { t } = useLang();
  const { showToast } = useToast();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) {
      void Promise.resolve().then(() => {
        setReason("");
        setBusy(false);
      });
    }
  }, [open]);

  const confirm = async () => {
    setBusy(true);
    try {
      await invoke("set_allowlist_entry", {
        imagePath,
        name: processName,
        trusted: true,
        reason: reason.trim() ? reason.trim() : null,
      });
      showToast(t("allowlist.trustedToast"), "success");
      onCompleted();
      onClose();
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          className="fixed inset-0 z-55 flex items-center justify-center bg-black/45 p-4"
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
            aria-labelledby="iam-title"
            className="w-full max-w-md rounded-xl border border-(--border) bg-(--surface) p-5 shadow-xl"
            initial={{ scale: 0.98, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.98, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="iam-title" className="text-base font-semibold">
              {t("processes.actions.ignoreConfirmTitle")}
            </h2>
            <p className="mt-2 text-sm text-(--muted)">
              {t("processes.actions.ignoreConfirmDescription")}
            </p>
            <p className="mt-3 font-mono text-xs text-(--foreground) break-all">
              {imagePath}
            </p>
            <label className="mt-4 block text-sm">
              <span className="text-(--muted)">
                {t("processes.actions.reasonPlaceholder")}
              </span>
              <input
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                autoComplete="off"
                className="mt-1 w-full rounded-lg border border-(--border) bg-(--background)/80 px-3 py-2 text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
              />
            </label>
            <div className="mt-5 flex flex-wrap justify-end gap-2 border-t border-(--border) pt-4">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-(--border) px-4 py-2 text-sm font-medium transition-colors duration-200 hover:bg-(--surface-2)"
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void confirm()}
                className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? t("common.loading") : t("common.confirm")}
              </button>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
