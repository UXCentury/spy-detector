import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { ToastProvider } from "@/components/Toast";
import {
  NotificationCenterProvider,
  useNotificationCenter,
} from "@/components/notifications/NotificationCenter";
import { LangProvider } from "@/lib/i18nContext";

const toastMocks = vi.hoisted(() => ({
  showNotificationToast: vi.fn(),
  showToast: vi.fn(),
}));

vi.mock("@/components/Toast", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/components/Toast")>();
  return {
    ...actual,
    useToast: () => ({
      showToast: toastMocks.showToast,
      showNotificationToast: toastMocks.showNotificationToast,
    }),
  };
});

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
  }),
}));

function PushHarness() {
  const { push } = useNotificationCenter();
  return (
    <button
      type="button"
      onClick={() =>
        push({
          severity: "info",
          icon: "scan",
          title: "Hello",
        })
      }
    >
      Push
    </button>
  );
}

function NotificationLen() {
  const { notifications } = useNotificationCenter();
  return <span data-testid="notif-len">{notifications.length}</span>;
}

describe("NotificationCenterProvider", () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem("notif:inApp", "false");
    toastMocks.showNotificationToast.mockClear();
    toastMocks.showToast.mockClear();
  });

  it("does not enqueue in-app toast when prefs.inApp is false", async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <LangProvider>
          <NotificationCenterProvider>
            <NotificationLen />
            <PushHarness />
          </NotificationCenterProvider>
        </LangProvider>
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /^push$/i }));

    expect(toastMocks.showNotificationToast).not.toHaveBeenCalled();
    expect(screen.getByTestId("notif-len")).toHaveTextContent("0");
  });
});
