"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { usePathname, useRouter } from "next/navigation";
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { AppShell } from "@/components/AppShell";
import { PulseDot } from "@/components/PulseDot";
import { type Lang, parseLang } from "@/lib/i18n";

type SplashProgressPayload = {
  step: string;
  label: string;
  done: number;
  total: number;
};

function isStandalonePath(pathname: string): boolean {
  return pathname.startsWith("/onboarding");
}

export function AppGate({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const standalone = useMemo(() => isStandalonePath(pathname), [pathname]);
  const frontendSetupDoneRef = useRef(false);

  const [, setSplashProgress] = useState<SplashProgressPayload | null>(null);

  const [resolved, setResolved] = useState(() => standalone);
  const [language, setLanguage] = useState<Lang | null>(null);
  const [termsAt, setTermsAt] = useState<string | null>(null);

  const markFrontendSetupComplete = useCallback(() => {
    if (frontendSetupDoneRef.current) return;
    frontendSetupDoneRef.current = true;
    void invoke("set_complete", { task: "frontend" }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!isTauri()) {
      markFrontendSetupComplete();
      return;
    }
    if (standalone) {
      markFrontendSetupComplete();
      return;
    }
    if (!resolved) return;

    let cancelled = false;
    let unlistenTick: (() => void) | undefined;
    let unlistenProgress: (() => void) | undefined;

    const cleanup = () => {
      unlistenTick?.();
      unlistenProgress?.();
    };

    function finish() {
      if (cancelled) return;
      cancelled = true;
      cleanup();
      clearTimeout(timeoutHandle);
      markFrontendSetupComplete();
    }

    const timeoutHandle = setTimeout(finish, 8000);

    void listen<SplashProgressPayload>("splash_progress", (event) => {
      if (cancelled) return;
      setSplashProgress(event.payload);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenProgress = fn;
    });

    void (async () => {
      try {
        await Promise.all([
          invoke("get_runtime_status"),
          invoke("get_app_settings"),
        ]);
        if (!cancelled) finish();
      } catch {
        // Fall back to monitoring_tick or hard timeout.
      }
    })();

    void listen("monitoring_tick", () => {
      finish();
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenTick = fn;
    });

    return () => {
      cancelled = true;
      cleanup();
      clearTimeout(timeoutHandle);
    };
  }, [standalone, resolved, markFrontendSetupComplete]);

  useEffect(() => {
    if (standalone) {
      queueMicrotask(() => setResolved(true));
      return;
    }

    if (!isTauri()) {
      queueMicrotask(() => {
        setLanguage("en-US");
        setTermsAt("web");
        setResolved(true);
      });
      return;
    }

    let cancelled = false;
    queueMicrotask(() => setResolved(false));

    void (async () => {
      try {
        const [langRaw, terms] = await Promise.all([
          invoke<string | null>("get_language"),
          invoke<string | null>("get_terms_accepted_at"),
        ]);
        if (cancelled) return;
        setLanguage(parseLang(langRaw));
        setTermsAt(typeof terms === "string" && terms.length > 0 ? terms : null);
      } catch {
        if (!cancelled) {
          setLanguage(null);
          setTermsAt(null);
        }
      } finally {
        if (!cancelled) setResolved(true);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [standalone]);

  useEffect(() => {
    if (standalone || !resolved) return;
    if (!isTauri()) return;
    if (language === null) {
      router.replace("/onboarding/language/");
      return;
    }
    if (termsAt === null) {
      router.replace("/onboarding/terms/");
    }
  }, [standalone, resolved, language, termsAt, router]);

  if (standalone) {
    return <>{children}</>;
  }

  if (!resolved) {
    return (
      <div className="flex h-dvh items-center justify-center bg-(--background)">
        <PulseDot className="scale-125" />
      </div>
    );
  }

  if (!isTauri()) {
    return <AppShell>{children}</AppShell>;
  }

  if (language === null || termsAt === null) {
    return (
      <div className="flex h-dvh items-center justify-center bg-(--background)">
        <PulseDot className="scale-125" />
      </div>
    );
  }

  return <AppShell>{children}</AppShell>;
}
