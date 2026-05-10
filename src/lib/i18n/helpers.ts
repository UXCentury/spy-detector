import { strings } from "./catalog";
import { LANGS, type Lang, type StringKey } from "./types";

export function isLang(value: string): value is Lang {
  return (LANGS as readonly string[]).includes(value);
}

export function parseLang(raw: string | null | undefined): Lang | null {
  if (!raw || !isLang(raw)) return null;
  return raw;
}

export function isRtlLang(lang: Lang | null): boolean {
  if (!lang) return false;
  return lang === "ar" || lang === "he" || lang === "fa";
}

/** Resolve a string outside React (e.g. onboarding preview with arbitrary Lang). */
export function translate(key: StringKey, lang: Lang | null): string {
  const row = strings[key];
  const code = lang ?? "en-US";
  return row[code] ?? row["en-US"] ?? "";
}
