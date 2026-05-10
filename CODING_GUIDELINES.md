# Coding guidelines

Spy Detector pairs a **Next.js** frontend with a **Tauri 2** Rust backend. These conventions keep the codebase consistent and safe for security-sensitive behavior.

## Frontend (TypeScript, Next.js 16, React 19, Tailwind 4)

### Structure

- Use the **App Router**. Routes live under **`src/app/`**.
- Shared UI belongs in **`src/components/`** (including feature folders such as `overview/`).
- Reusable hooks live under **`src/lib/hooks/`**.

### Styling

- Prefer Tailwind 4 **shorthand** for CSS variables: `bg-(--surface)`, `text-(--muted)`, `border-(--border)` — not `bg-[var(--surface)]`.
- Use severity tokens: **`(--severity-low)`**, **`(--severity-warn)`**, **`(--severity-high)`** instead of hard-coded greens, yellows, or reds.

### Copy and icons

- All user-visible strings go through **`useLang()`** from `@/lib/i18nContext` and **`t('key')`**. Do not leave raw English in JSX.
- Prefer **`lucide-react`** icons. Do not hand-inline SVG when an equivalent Lucide icon exists.

### Components

Reuse primitives before adding new ones, including: **`Toggle`**, **`Slider`**, **`SettingSection`**, **`Skeleton`**, **`PulseDot`**, **`AnimatedNumber`**, **`ScoreGauge`**, **`Sparkline`**, **`SeverityDonut`**, **`StatCard`**, **`ProgressBar`**.

### Motion

- Use **`framer-motion`** for row transitions, modals, and similar UI motion.

### Rendering model

- The UI is built as a **static export** consumed by Tauri. Avoid **`next/font`** server assumptions, **Route Handlers**, and **`getServerSideProps`**-style patterns. No reliance on server-only APIs for core flows.

### Tone

- No emojis in code or user-facing copy unless explicitly requested.

## Backend (Rust)

### Layout

- Detector and subsystem code lives under **`src-tauri/src/`**, typically **one module per major concern**.

### IPC

- Commands should return **`Result<T, String>`** (or equivalent stringifiable errors) so the frontend can surface failures as toasts.

### Async

- Long-running tasks tied to the Tauri runtime should use **`tauri::async_runtime::spawn`**. Avoid **`tokio::spawn`** for work that must integrate cleanly with Tauri-managed tasks unless there is an established pattern.

### Real-time monitors

- Export **`pub fn is_running() -> bool`** backed by a **`pub static FOO_ACTIVE: AtomicBool`** when the heartbeat must reflect subsystem state (`monitoring.rs` consumes these flags).
- Never panic the whole process on monitor failure — **log**, reset state, and continue.
- Gate privileged collectors on **`privilege::is_elevated()`** when kernel or protected APIs require admin.

### Database

- SQLite lives at **`%APPDATA%\spy-detector\db.sqlite`** (opened via **`db.rs`**).
- Migrations must be **idempotent**: `CREATE TABLE IF NOT EXISTS`, and **`ALTER TABLE`** guarded so reruns are safe.

### Dangerous actions

- **Kill** and **quarantine** must require the **SHA-256 confirmation token** prepared by the frontend flow. Never act on a bare PID without the established handshake.

## Internationalization

- English strings are defined in **`src/lib/i18n/english.ts`** (plus **`bootstrap.ts`** for splash-only keys).
- Missing translations must **fail open** to English — do not throw on unknown keys.
- Locale identifiers follow **IETF BCP 47** (`en-US`, `hy-AM`, `zh-CN`, …).

## Privacy and data handling

- Scan results and configuration stay **local**. There is **no telemetry** by default.
- In-app **bug reports** are **opt-in** and should only include material the user attaches.
- **IOC refresh** performs an outbound **GET** to a public URL; it must not exfiltrate private scan content.

## Performance expectations

- Avoid tight loops that repeatedly enumerate processes or hit IPC — batch work and reuse existing events (`monitoring_tick`, scan completion, etc.).
- **ETW** callbacks must stay **non-blocking**; use bounded queues if you must decouple processing from the provider thread.
- Live alert timelines should cap retained rows (the alerts UI keeps a bounded recent window — follow that pattern for similar feeds).

## Code style

### TypeScript

- Avoid **`any`**. At IPC boundaries, prefer **`unknown`** plus narrowing.

### Rust

- Run **`cargo fmt`** before submitting.
- Aim for **`cargo clippy --all-targets -- -D warnings`** clean.

### Comments

- Comment **why** non-obvious decisions were made, not **what** the next line does.
