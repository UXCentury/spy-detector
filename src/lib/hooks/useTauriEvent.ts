import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useLayoutEffect, useRef } from "react";

export function useTauriEvent<T>(name: string, handler: (e: Event<T>) => void) {
  const ref = useRef(handler);
  useLayoutEffect(() => {
    ref.current = handler;
  }, [handler]);
  useEffect(() => {
    let un: UnlistenFn | null = null;
    let cancelled = false;
    void (async () => {
      const u = await listen<T>(name, (e) => ref.current(e));
      if (cancelled) u();
      else un = u;
    })();
    return () => {
      cancelled = true;
      if (un) un();
    };
  }, [name]);
}
