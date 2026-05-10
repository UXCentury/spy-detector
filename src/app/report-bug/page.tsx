"use client";

import { invoke } from "@tauri-apps/api/core";
import { Bug, Mail } from "lucide-react";
import { useCallback, useState } from "react";
import { usePageReady } from "@/lib/PageStatus";
import { ProgressBar } from "@/components/ProgressBar";
import { useToast } from "@/components/Toast";
import { useLang } from "@/lib/i18nContext";
import { openExternal } from "@/lib/openExternal";

type Saved = { path: string };

export default function ReportBugPage() {
  const { t } = useLang();
  const { showToast } = useToast();
  usePageReady(true);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [includeDiagnostics, setIncludeDiagnostics] = useState(true);
  const [busy, setBusy] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);

  const submit = useCallback(async () => {
    setBusy(true);
    setSavedPath(null);
    try {
      const r = await invoke<Saved>("submit_bug_report", {
        payload: {
          title: title.trim(),
          description,
          includeDiagnostics,
        },
      });
      setSavedPath(r.path);
      showToast(t("reportBug.success"), "success");
    } catch (e) {
      showToast(e instanceof Error ? e.message : String(e), "error");
    } finally {
      setBusy(false);
    }
  }, [description, includeDiagnostics, showToast, title, t]);

  const copyPath = async () => {
    if (!savedPath) return;
    try {
      await navigator.clipboard.writeText(savedPath);
      showToast(t("settings.toast.pathCopied"), "success");
    } catch {
      showToast(t("reportBug.copyFailed"), "error");
    }
  };

  const mailtoHref = (() => {
    const subj = encodeURIComponent(
      title.trim() || t("reportBug.defaultSubject"),
    );
    const body = encodeURIComponent(
      `${description}\n\n(saved report path: ${savedPath ?? "not saved yet"})`,
    );
    return `mailto:?subject=${subj}&body=${body}`;
  })();

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Bug className="size-6 text-(--accent-2)" aria-hidden />
          <h1 className="text-2xl font-semibold tracking-tight">{t("reportBug.title")}</h1>
        </div>
        <p className="mt-2 text-sm text-(--muted)">{t("reportBug.subtitle")}</p>
      </div>

      <div className="space-y-4 rounded-xl border border-(--border) bg-(--surface)/70 p-6 backdrop-blur-md">
        <label className="block text-sm">
          <span className="text-(--muted)">{t("reportBug.titleLabel")}</span>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="mt-1 w-full rounded-lg border border-(--border) bg-(--background)/80 px-3 py-2 text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
          />
        </label>
        <label className="block text-sm">
          <span className="text-(--muted)">
            {t("reportBug.descriptionLabel")}
          </span>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={6}
            className="mt-1 w-full resize-y rounded-lg border border-(--border) bg-(--background)/80 px-3 py-2 text-sm transition-colors duration-200 focus:border-(--accent) focus:outline-none"
          />
        </label>
        <label className="flex cursor-pointer items-start gap-3 text-sm">
          <input
            type="checkbox"
            checked={includeDiagnostics}
            onChange={(e) => setIncludeDiagnostics(e.target.checked)}
            className="mt-1 size-4 rounded border-(--border) accent-(--accent)"
          />
          <span>
            <span className="font-medium text-(--foreground)">
              {t("reportBug.includeDiagnostics")}
            </span>
            <span className="mt-0.5 block text-(--muted)">
              {t("reportBug.diagnosticsHint")}
            </span>
          </span>
        </label>

        <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
          <button
            type="button"
            disabled={busy || !title.trim()}
            onClick={() => void submit()}
            className="rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white transition-opacity duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? t("reportBug.saving") : t("reportBug.submit")}
          </button>
          <a
            href={mailtoHref}
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-(--border) px-4 py-2 text-sm font-medium text-(--foreground) transition-colors duration-200 hover:bg-(--surface-2)"
            onClick={(e) => {
              e.preventDefault();
              void openExternal(mailtoHref);
            }}
          >
            <Mail className="size-4" aria-hidden />
            {t("reportBug.openMail")}
          </a>
          {busy ? <ProgressBar className="min-w-[140px] flex-1 sm:max-w-xs" /> : null}
        </div>
      </div>

      {savedPath ? (
        <div className="rounded-xl border border-(--border) bg-(--surface)/60 px-4 py-3 text-sm">
          <div className="text-(--muted)">{t("reportBug.savedTo")}</div>
          <div className="mt-1 break-all font-mono text-xs text-(--foreground)">
            {savedPath}
          </div>
          <button
            type="button"
            onClick={() => void copyPath()}
            className="mt-3 rounded-lg border border-(--border) px-3 py-1.5 text-xs font-medium transition-colors duration-200 hover:bg-(--surface-2)"
          >
            {t("reportBug.copyPath")}
          </button>
        </div>
      ) : null}
    </div>
  );
}
