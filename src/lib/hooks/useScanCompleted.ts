import type { Event } from "@tauri-apps/api/event";
import { useLayoutEffect, useRef } from "react";

import type { ScanCompletedEvent } from "@/lib/types/monitoring";

import { useTauriEvent } from "./useTauriEvent";

export function useScanCompleted(
  onCompleted: (e: Event<ScanCompletedEvent>) => void,
) {
  const ref = useRef(onCompleted);
  useLayoutEffect(() => {
    ref.current = onCompleted;
  }, [onCompleted]);

  useTauriEvent<ScanCompletedEvent>("scan_completed", (e) => {
    ref.current(e);
  });
}
