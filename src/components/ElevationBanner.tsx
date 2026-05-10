"use client";

import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import { ProgressBar } from "@/components/ProgressBar";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";

export function ElevationBanner() {
  const { t } = useLang();
  const { showToast } = useToast();
  const [busy, setBusy] = useState(false);

  async function restartElevated() {
    setBusy(true);
    try {
      await invoke("request_elevation_restart");
    } catch (e) {
      setBusy(false);
      showToast(
        `${t("elevation.errorPrefix")} ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  return (
    <div
      role="status"
      className="border-b border-(--severity-warn)/35 bg-(--severity-warn)/10 px-4 py-3 text-sm text-(--foreground) md:px-8"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
        <p className="min-w-0 flex-1 leading-relaxed text-(--muted)">
          {t("elevation.banner")}
        </p>
        <div className="flex shrink-0 flex-col gap-2 sm:items-end">
          <button
            type="button"
            disabled={busy}
            onClick={() => void restartElevated()}
            className="rounded-lg border border-(--severity-warn)/50 bg-(--surface)/80 px-3 py-2 text-xs font-medium transition-colors duration-200 hover:bg-(--surface-2) disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? t("elevation.starting") : t("elevation.restartButton")}
          </button>
          {busy ? <ProgressBar className="w-40 sm:w-48" /> : null}
        </div>
      </div>
    </div>
  );
}
