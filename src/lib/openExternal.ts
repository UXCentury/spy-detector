import { isTauri } from "@tauri-apps/api/core";

export async function openExternal(url: string): Promise<void> {
  if (!url) return;
  try {
    if (isTauri()) {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(url);
      return;
    }
  } catch (err) {
    console.error("[openExternal] plugin-opener failed", err);
  }
  try {
    window.open(url, "_blank", "noopener,noreferrer");
  } catch (err) {
    console.error("[openExternal] window.open failed", err);
  }
}
