"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { motion } from "framer-motion";
import { Check, Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ONBOARDING_LANGUAGES } from "@/lib/onboardingLanguages";
import { parseLang, type Lang } from "@/lib/i18n";
import { useLang } from "@/lib/i18nContext";

export default function OnboardingLanguagePage() {
  const { tLang, setLang } = useLang();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Lang>("en-US");
  const [displayLang, setDisplayLang] = useState<Lang | null>(null);

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void (async () => {
      try {
        const raw = await invoke<string | null>("get_language");
        const terms = await invoke<string | null>("get_terms_accepted_at");
        if (cancelled) return;
        const lang = parseLang(raw);
        setDisplayLang(lang);
        if (lang && typeof terms === "string" && terms.length > 0) {
          router.replace("/");
        }
      } catch {
        /* ignore */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ONBOARDING_LANGUAGES;
    return ONBOARDING_LANGUAGES.filter(
      (row) =>
        row.native.toLowerCase().includes(q) ||
        row.english.toLowerCase().includes(q) ||
        row.code.toLowerCase().includes(q),
    );
  }, [query]);

  const previewLang = displayLang ?? selected;

  const onContinue = async () => {
    if (!isTauri()) {
      router.replace("/onboarding/terms/");
      return;
    }
    try {
      await invoke("set_language", { code: selected });
      setLang(selected);
      router.replace("/onboarding/terms/");
    } catch {
      /* toast optional */
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="mx-auto flex max-w-4xl flex-col gap-8 px-4 py-8 md:px-8 md:py-10"
    >
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-(--foreground)">
          {tLang("chooseLanguage", previewLang)}
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-(--muted)">
          {tLang("onboarding.footerNote", previewLang)}
        </p>
      </div>

      <div className="relative">
        <Search
          className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-(--muted)"
          aria-hidden
        />
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={tLang("onboarding.searchLanguages", previewLang)}
          className="w-full rounded-xl border border-(--border) bg-(--surface) py-2.5 pl-10 pr-3 text-sm text-(--foreground) outline-none ring-(--accent)/40 placeholder:text-(--muted) focus-visible:ring-2"
        />
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        {filtered.map((row) => {
          const active = selected === row.code;
          return (
            <motion.button
              key={row.code}
              type="button"
              layout
              onClick={() => setSelected(row.code)}
              whileTap={{ scale: 0.98 }}
              className={`flex flex-col gap-2 rounded-xl border px-4 py-4 text-left transition-colors duration-150 ${
                active
                  ? "border-(--accent) bg-(--accent)/12 shadow-[0_0_0_1px_var(--accent)]/25"
                  : "border-(--border) bg-(--surface) hover:bg-(--surface-2)"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <span
                  className="text-4xl leading-none"
                  style={{
                    fontFamily: '"Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", sans-serif',
                  }}
                  aria-hidden
                >
                  {row.flag}
                </span>
                {active ? (
                  <Check className="size-5 shrink-0 text-(--accent)" aria-hidden />
                ) : (
                  <span className="size-5 shrink-0" aria-hidden />
                )}
              </div>
              <div>
                <div className="text-base font-semibold text-(--foreground)">
                  {row.native}
                </div>
                <div className="mt-1 text-xs text-(--muted)">{row.english}</div>
              </div>
            </motion.button>
          );
        })}
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="sticky bottom-0 border-t border-(--border) bg-(--background)/90 py-4 backdrop-blur-md md:static md:border-0 md:bg-transparent md:py-0"
      >
        <motion.button
          type="button"
          onClick={() => void onContinue()}
          whileTap={{ scale: 0.98 }}
          className="w-full rounded-xl bg-(--accent) px-5 py-3 text-sm font-semibold text-white transition-opacity duration-150 hover:opacity-90 md:w-auto md:min-w-[200px]"
        >
          {tLang("continue", previewLang)}
        </motion.button>
      </motion.div>
    </motion.div>
  );
}
