import "@testing-library/jest-dom/vitest";
import { invoke } from "@tauri-apps/api/core";
import { afterEach, vi } from "vitest";

import { tauriListenBridge } from "@/test-utils/tauriListenBridge";

globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
  isTauri: () => false,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(
    async (channel: string, handler: (e: { payload: unknown }) => void) => {
      tauriListenBridge.register(channel, handler);
      return () => tauriListenBridge.unregister(channel);
    },
  ),
  emit: vi.fn(),
}));

vi.mock("@tauri-apps/api/webviewWindow", () => ({
  WebviewWindow: {
    getCurrent: () => ({
      isMaximized: vi.fn().mockResolvedValue(false),
      isMinimized: vi.fn().mockResolvedValue(false),
      isVisible: vi.fn().mockResolvedValue(true),
      minimize: vi.fn(),
      maximize: vi.fn(),
      close: vi.fn(),
      toggleMaximize: vi.fn(),
      onResized: vi.fn(async () => () => {}),
    }),
  },
}));

vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(true),
  requestPermission: vi.fn().mockResolvedValue("granted"),
  sendNotification: vi.fn(),
}));

afterEach(() => {
  vi.mocked(invoke).mockReset();
  tauriListenBridge.reset();
});
