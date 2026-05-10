"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { parseLang, strings, type Lang, type StringKey } from "@/lib/i18n";

export type LangContextValue = {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: StringKey) => string;
  /** Resolve copy for an arbitrary locale (e.g. language picker preview). */
  tLang: (key: StringKey, l: Lang) => string;
};

const LangContext = createContext<LangContextValue | null>(null);

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en-US");

  useEffect(() => {
    if (!isTauri()) return;
    invoke<string | null>("get_language")
      .then((code) => {
        const parsed = parseLang(code);
        if (parsed) setLangState(parsed);
      })
      .catch(() => {});
  }, []);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
  }, []);

  const t = useCallback(
    (key: StringKey) =>
      strings[key]?.[lang] ?? strings[key]?.["en-US"] ?? "",
    [lang],
  );

  const tLang = useCallback(
    (key: StringKey, l: Lang) =>
      strings[key]?.[l] ?? strings[key]?.["en-US"] ?? "",
    [],
  );

  const value = useMemo(
    () => ({ lang, setLang, t, tLang }),
    [lang, setLang, t, tLang],
  );

  return (
    <LangContext.Provider value={value}>{children}</LangContext.Provider>
  );
}

export function useLang(): LangContextValue {
  const ctx = useContext(LangContext);
  if (!ctx) {
    throw new Error("useLang must be used within LangProvider");
  }
  return ctx;
}
