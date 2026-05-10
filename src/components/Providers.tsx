"use client";

import { CommandPaletteProvider } from "@/components/CommandPalette/CommandPaletteProvider";
import {
  NotificationCenterProvider,
} from "@/components/notifications/NotificationCenter";
import { NotificationListener } from "@/components/notifications/NotificationListener";
import { SoundProvider } from "@/components/SoundProvider";
import { ToastProvider } from "@/components/Toast";
import { LangProvider } from "@/lib/i18nContext";
import { PageStatusProvider } from "@/lib/PageStatus";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ToastProvider>
      <LangProvider>
        <PageStatusProvider>
          <SoundProvider>
            <CommandPaletteProvider>
              <NotificationCenterProvider>
                <NotificationListener />
                {children}
              </NotificationCenterProvider>
            </CommandPaletteProvider>
          </SoundProvider>
        </PageStatusProvider>
      </LangProvider>
    </ToastProvider>
  );
}
