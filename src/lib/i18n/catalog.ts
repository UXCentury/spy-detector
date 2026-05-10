import {
  onboardingAccept,
  onboardingChooseLanguage,
  onboardingContinue,
  onboardingDecline,
  onboardingInitializing,
  onboardingTerms,
} from "./bootstrap";
import { ENGLISH } from "./english";
import { PRIORITY_LOCALES } from "./priority-locales";
import { LANGS, type Lang, type StringKey } from "./types";

function buildStrings(): Record<StringKey, Partial<Record<Lang, string>>> {
  const out = {} as Record<StringKey, Partial<Record<Lang, string>>>;
  for (const key of Object.keys(ENGLISH) as StringKey[]) {
    out[key] = { "en-US": ENGLISH[key] };
  }

  const mergeOnboarding = (
    key: StringKey,
    map: Partial<Record<Lang, string>>,
  ) => {
    out[key] = { ...out[key], ...map };
  };

  mergeOnboarding("initializing", onboardingInitializing);
  mergeOnboarding("chooseLanguage", onboardingChooseLanguage);
  mergeOnboarding("continue", onboardingContinue);
  mergeOnboarding("terms", onboardingTerms);
  mergeOnboarding("accept", onboardingAccept);
  mergeOnboarding("decline", onboardingDecline);

  for (const lang of LANGS) {
    const patch = PRIORITY_LOCALES[lang];
    if (!patch) continue;
    for (const k of Object.keys(patch) as StringKey[]) {
      const val = patch[k];
      if (val !== undefined) {
        out[k] = { ...out[k], [lang]: val };
      }
    }
  }

  return out;
}

export const strings = buildStrings();
