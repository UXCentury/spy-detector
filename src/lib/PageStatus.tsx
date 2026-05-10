"use client";

import { usePathname } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export function normalizePagePath(path: string): string {
  const p = path.replace(/\/$/, "") || "/";
  return p;
}

export type PageStatusContextValue = {
  readyPath: string | null;
  setPageReady: (path: string) => void;
};

const PageStatusContext = createContext<PageStatusContextValue | null>(null);

export function PageStatusProvider({ children }: { children: ReactNode }) {
  const [readyPath, setReadyPathState] = useState<string | null>(null);
  const routePath = normalizePagePath(usePathname() ?? "/");
  const routePathRef = useRef(routePath);
  useLayoutEffect(() => {
    routePathRef.current = routePath;
  }, [routePath]);

  const setPageReady = useCallback((path: string) => {
    const n = normalizePagePath(path);
    if (n !== routePathRef.current) return;
    setReadyPathState(n);
  }, []);

  useEffect(() => {
    const id = window.setTimeout(() => {
      setReadyPathState(routePath);
    }, 2000);
    return () => window.clearTimeout(id);
  }, [routePath]);

  const value = useMemo(
    () => ({ readyPath, setPageReady }),
    [readyPath, setPageReady],
  );

  return (
    <PageStatusContext.Provider value={value}>{children}</PageStatusContext.Provider>
  );
}

export function usePageStatus(): PageStatusContextValue {
  const ctx = useContext(PageStatusContext);
  if (!ctx) {
    throw new Error("usePageStatus must be used within PageStatusProvider");
  }
  return ctx;
}

export function usePageReady(ready: boolean) {
  const pathname = usePathname();
  const { setPageReady } = usePageStatus();

  useEffect(() => {
    if (!ready) return;
    setPageReady(normalizePagePath(pathname ?? "/"));
  }, [ready, pathname, setPageReady]);
}
