"use client";

import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { Copy, Eye, Minus, Shield, Square, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getAppMetadataSync,
  useAppMetadata,
} from "@/lib/hooks/useAppMetadata";

export function MinimalWindowHeader({
  subtitle,
}: {
  subtitle?: string;
}) {
  const meta = useAppMetadata();
  const metaSync = useMemo(() => getAppMetadataSync(), []);
  const [maximized, setMaximized] = useState(false);

  const syncMaximized = useCallback(async () => {
    try {
      const w = WebviewWindow.getCurrent();
      setMaximized(await w.isMaximized());
    } catch {
      setMaximized(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => void syncMaximized());
    let unResize: (() => void) | undefined;
    let cancelled = false;
    void (async () => {
      try {
        const w = WebviewWindow.getCurrent();
        unResize = await w.onResized(() => {
          void syncMaximized();
        });
      } catch {
        /* not in Tauri */
      }
      if (cancelled && unResize) unResize();
    })();
    return () => {
      cancelled = true;
      if (unResize) unResize();
    };
  }, [syncMaximized]);

  const onMinimize = () => {
    void WebviewWindow.getCurrent().minimize();
  };

  const onToggleMaximize = () => {
    void WebviewWindow.getCurrent().toggleMaximize().then(() => syncMaximized());
  };

  const onClose = () => {
    void WebviewWindow.getCurrent().close();
  };

  return (
    <header
      className="flex h-9 w-full shrink-0 items-center border-b border-(--border) bg-(--surface)/95 px-2 backdrop-blur-md"
      style={{
        backgroundImage:
          "linear-gradient(180deg, rgba(255,255,255,0.03) 0%, transparent 65%)",
      }}
    >
      <div className="flex min-w-0 flex-[0_1_auto] items-center gap-2 pl-1 md:pl-2">
        <Eye className="size-4 shrink-0 text-(--accent)" aria-hidden />
        <span className="truncate text-sm font-semibold tracking-tight text-(--foreground)">
          Spy Detector
        </span>
        {subtitle ? (
          <>
            <span
              className="hidden h-4 w-px shrink-0 bg-(--border-bright)/50 sm:block"
              aria-hidden
            />
            <span className="hidden truncate text-xs text-(--muted) sm:inline">
              {subtitle}
            </span>
          </>
        ) : null}
        <span
          className="ml-1 shrink-0 font-mono text-[9px] tabular-nums text-(--muted)"
          data-tauri-drag-region="false"
          aria-hidden
        >
          v{(meta ?? metaSync).version}
        </span>
      </div>

      <div
        className="flex min-h-9 min-w-8 flex-1 items-stretch"
        data-tauri-drag-region
      />

      <div className="flex flex-[0_1_auto] items-center gap-2 pr-1 md:pr-2">
        <div
          className="hidden items-center gap-2 rounded-lg border border-(--border) bg-(--surface-2)/50 px-2 py-0.5 sm:flex"
          data-tauri-drag-region="false"
        >
          <Shield className="size-3.5 text-(--muted)" aria-hidden />
          <span className="text-[10px] font-medium text-(--muted)">Setup</span>
        </div>

        <div className="flex items-center" data-tauri-drag-region="false">
          <button
            type="button"
            onClick={onMinimize}
            className="flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--accent)"
            aria-label="Minimize"
          >
            <Minus className="size-3.5" strokeWidth={2} />
          </button>
          <button
            type="button"
            onClick={onToggleMaximize}
            className="flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--surface-2) hover:text-(--foreground) focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--accent)"
            aria-label={maximized ? "Restore" : "Maximize"}
          >
            {maximized ? (
              <Copy className="size-3.5" strokeWidth={2} />
            ) : (
              <Square className="size-3.5" strokeWidth={2} />
            )}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="flex size-8 items-center justify-center rounded-md text-(--muted) transition-colors hover:bg-(--severity-high) hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--severity-high)"
            aria-label="Close"
          >
            <X className="size-3.5" strokeWidth={2} />
          </button>
        </div>
      </div>
    </header>
  );
}
