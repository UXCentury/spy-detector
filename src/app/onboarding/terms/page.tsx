"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { isRtlLang, parseLang, translate, type Lang } from "@/lib/i18n";

export default function OnboardingTermsPage() {
  const router = useRouter();
  const [lang, setLang] = useState<Lang | null>(() =>
    !isTauri() ? "en-US" : null,
  );
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!isTauri()) {
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const raw = await invoke<string | null>("get_language");
        const terms = await invoke<string | null>("get_terms_accepted_at");
        if (cancelled) return;
        const parsed = parseLang(raw);
        setLang(parsed);
        if (parsed && typeof terms === "string" && terms.length > 0) {
          router.replace("/");
        }
        if (!parsed) {
          router.replace("/onboarding/language/");
        }
      } catch {
        if (!cancelled) router.replace("/onboarding/language/");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  const rtl = isRtlLang(lang);

  const onAccept = async () => {
    setBusy(true);
    try {
      if (isTauri()) {
        await invoke("accept_terms");
      }
      router.replace("/");
    } finally {
      setBusy(false);
    }
  };

  const onQuit = async () => {
    if (!isTauri()) {
      router.replace("/");
      return;
    }
    try {
      await invoke("quit_app");
    } catch {
      window.close();
    }
  };

  const effectiveLang = lang;

  return (
    <motion.div
      initial={{ opacity: 0, x: 12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="mx-auto flex max-w-2xl flex-col gap-8 px-4 py-8 md:px-8 md:py-10"
    >
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-(--foreground)">
          {translate("terms", effectiveLang)}
        </h1>
      </div>

      <div
        dir={rtl ? "rtl" : "ltr"}
        className="space-y-4 rounded-xl border border-(--border) bg-(--surface) p-5 text-sm leading-relaxed text-(--muted)"
      >
        {translate("termsBody", effectiveLang)
          .split("\n\n")
          .map((para, idx) => (
            <p key={idx}>{para}</p>
          ))}
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
        <motion.button
          type="button"
          disabled={busy}
          onClick={() => void onAccept()}
          whileTap={{ scale: busy ? 1 : 0.98 }}
          className="rounded-xl bg-(--accent) px-5 py-3 text-sm font-semibold text-white transition-opacity duration-150 hover:opacity-90 disabled:opacity-50"
        >
          {translate("accept", effectiveLang)}
        </motion.button>
        <motion.button
          type="button"
          disabled={busy}
          onClick={() => void onQuit()}
          whileTap={{ scale: busy ? 1 : 0.98 }}
          className="rounded-xl border border-(--severity-high)/55 bg-(--severity-high)/12 px-5 py-3 text-sm font-semibold text-(--severity-high) transition-colors duration-150 hover:bg-(--severity-high)/20 disabled:opacity-50"
        >
          {translate("decline", effectiveLang)}
        </motion.button>
      </div>
    </motion.div>
  );
}
