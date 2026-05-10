"use client";

import { invoke, isTauri } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";

export type AppMetadata = {
  version: string;
  gitCommit: string;
  buildDate: string;
  tauriVersion: string;
  target: string;
};

export function getAppMetadataSync(): AppMetadata {
  const version =
    typeof process.env.NEXT_PUBLIC_APP_VERSION === "string"
      ? process.env.NEXT_PUBLIC_APP_VERSION
      : "0.1.0";
  return {
    version,
    gitCommit: "dev",
    buildDate: "",
    tauriVersion: "—",
    target:
      typeof navigator !== "undefined"
        ? `${navigator.platform ?? "web"}`
        : "web",
  };
}

export function useAppMetadata(): AppMetadata | null {
  const [meta, setMeta] = useState<AppMetadata | null>(() =>
    !isTauri()
      ? {
          version:
            typeof process.env.NEXT_PUBLIC_APP_VERSION === "string"
              ? process.env.NEXT_PUBLIC_APP_VERSION
              : "0.0.0",
          gitCommit: "dev",
          buildDate: "",
          tauriVersion: "—",
          target:
            typeof navigator !== "undefined"
              ? `${navigator.platform ?? "web"}`
              : "web",
        }
      : null,
  );

  useEffect(() => {
    if (!isTauri()) {
      return;
    }

    let cancelled = false;
    void invoke<AppMetadata>("get_app_metadata")
      .then((m) => {
        if (!cancelled) setMeta(m);
      })
      .catch(() => {
        if (!cancelled) setMeta(getAppMetadataSync());
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return meta;
}
