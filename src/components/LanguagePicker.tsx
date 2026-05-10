"use client";

import { motion } from "framer-motion";
import { Check, Search } from "lucide-react";
import { useMemo, useState } from "react";
import type { Lang } from "@/lib/i18n";
import { ONBOARDING_LANGUAGES } from "@/lib/onboardingLanguages";

type LanguagePickerProps = {
  selected: Lang;
  onSelect: (code: Lang) => void;
  searchPlaceholder: string;
};

export function LanguagePicker({
  selected,
  onSelect,
  searchPlaceholder,
}: LanguagePickerProps) {
  const [query, setQuery] = useState("");
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

  return (
    <>
      <div className="relative">
        <Search
          className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-(--muted)"
          aria-hidden
        />
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={searchPlaceholder}
          className="w-full rounded-xl border border-(--border) bg-(--surface) py-2.5 pl-10 pr-3 text-sm text-(--foreground) outline-none ring-(--accent)/40 placeholder:text-(--muted) focus-visible:ring-2"
        />
      </div>

      <div className="grid max-h-[min(52vh,28rem)] grid-cols-1 gap-3 overflow-y-auto pr-1 md:grid-cols-3">
        {filtered.map((row) => {
          const active = selected === row.code;
          return (
            <motion.button
              key={row.code}
              type="button"
              layout
              onClick={() => onSelect(row.code)}
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
                    fontFamily:
                      '"Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", sans-serif',
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
    </>
  );
}
