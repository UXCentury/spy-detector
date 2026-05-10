import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { ToastProvider } from "@/components/Toast";
import { LangProvider } from "@/lib/i18nContext";
import { PageStatusProvider } from "@/lib/PageStatus";

export function renderWithProviders(ui: ReactElement) {
  return render(<LangProvider>{ui}</LangProvider>);
}

export function renderWithLangAndToast(ui: ReactElement) {
  return render(
    <ToastProvider>
      <LangProvider>{ui}</LangProvider>
    </ToastProvider>,
  );
}

export function renderWithFullPageShell(ui: ReactElement) {
  return render(
    <ToastProvider>
      <LangProvider>
        <PageStatusProvider>{ui}</PageStatusProvider>
      </LangProvider>
    </ToastProvider>,
  );
}
