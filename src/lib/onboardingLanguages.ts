import type { Lang } from "@/lib/i18n";

export type OnboardingLanguageRow = {
  code: Lang;
  native: string;
  english: string;
  /** Regional-indicator pair as a single string */
  flag: string;
};

export const ONBOARDING_LANGUAGES: OnboardingLanguageRow[] = [
  {
    code: "hy-AM",
    native: "Հայերեն",
    english: "Armenian",
    flag: "\u{1F1E6}\u{1F1F2}",
  },
  { code: "en-US", native: "English", english: "English (United States)", flag: "\u{1F1FA}\u{1F1F8}" },
  { code: "en-GB", native: "English", english: "English (United Kingdom)", flag: "\u{1F1EC}\u{1F1E7}" },
  { code: "es", native: "Español", english: "Spanish", flag: "\u{1F1EA}\u{1F1F8}" },
  { code: "pt-BR", native: "Português (Brasil)", english: "Portuguese (Brazil)", flag: "\u{1F1E7}\u{1F1F7}" },
  { code: "fr", native: "Français", english: "French", flag: "\u{1F1EB}\u{1F1F7}" },
  { code: "de", native: "Deutsch", english: "German", flag: "\u{1F1E9}\u{1F1EA}" },
  { code: "it", native: "Italiano", english: "Italian", flag: "\u{1F1EE}\u{1F1F9}" },
  { code: "nl", native: "Nederlands", english: "Dutch", flag: "\u{1F1F3}\u{1F1F1}" },
  { code: "pl", native: "Polski", english: "Polish", flag: "\u{1F1F5}\u{1F1F1}" },
  { code: "ru", native: "Русский", english: "Russian", flag: "\u{1F1F7}\u{1F1FA}" },
  { code: "uk", native: "Українська", english: "Ukrainian", flag: "\u{1F1FA}\u{1F1E6}" },
  { code: "tr", native: "Türkçe", english: "Turkish", flag: "\u{1F1F9}\u{1F1F7}" },
  { code: "ar", native: "العربية", english: "Arabic", flag: "\u{1F1F8}\u{1F1E6}" },
  { code: "he", native: "עברית", english: "Hebrew", flag: "\u{1F1EE}\u{1F1F1}" },
  { code: "fa", native: "فارسی", english: "Persian", flag: "\u{1F1EE}\u{1F1F7}" },
  { code: "hi", native: "हिन्दी", english: "Hindi", flag: "\u{1F1EE}\u{1F1F3}" },
  { code: "bn", native: "বাংলা", english: "Bangla", flag: "\u{1F1E7}\u{1F1E9}" },
  { code: "zh-CN", native: "简体中文", english: "Chinese (Simplified)", flag: "\u{1F1E8}\u{1F1F3}" },
  { code: "zh-TW", native: "繁體中文", english: "Chinese (Traditional)", flag: "\u{1F1F9}\u{1F1FC}" },
  { code: "ja", native: "日本語", english: "Japanese", flag: "\u{1F1EF}\u{1F1F5}" },
  { code: "ko", native: "한국어", english: "Korean", flag: "\u{1F1F0}\u{1F1F7}" },
  { code: "vi", native: "Tiếng Việt", english: "Vietnamese", flag: "\u{1F1FB}\u{1F1F3}" },
  { code: "th", native: "ไทย", english: "Thai", flag: "\u{1F1F9}\u{1F1ED}" },
  { code: "id", native: "Bahasa Indonesia", english: "Indonesian", flag: "\u{1F1EE}\u{1F1E9}" },
];
