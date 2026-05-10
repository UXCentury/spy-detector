# Contributing to Spy Detector

## Welcome

Spy Detector is an open-source Windows spyware and stalkerware detector. It is built with **Tauri 2** and **Next.js**, maintained by **UXC LLC**, and distributed under the [MIT License](./LICENSE). Thank you for helping improve it.

## Code of conduct

Participation is governed by our [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By engaging with this project, you agree to uphold it.

## Getting started

### Prerequisites

- **Windows 10 or 11** (administrator rights recommended for full ETW-based detection).
- **Rust** stable (1.78 or newer recommended).
- **Node.js** 20+ and **npm**.
- **Visual Studio Build Tools** with the **Desktop development with C++** workload (required for the Windows Rust toolchain and native dependencies).
- **WebView2** runtime (standard on current Windows builds).

### Clone and install

```bash
git clone git@github.com:UXCentury/spy-detector.git
cd spy-detector
npm install
```

### Run in development

```bash
npm run tauri dev
```

This starts the Next.js dev server and the Tauri shell. The packaged dev flow runs **without** elevation by default (`asInvoker`). Full ETW coverage (for example kernel image-load tracing) requires elevation: use the in-app **Restart as administrator** control, or launch the dev terminal elevated.

### Known dev noise (Tauri + HMR)

During `npm run tauri dev`, the browser console may log **`[TAURI] Couldn't find callback id … This might happen when the app is reloaded while Rust is running an asynchronous operation.`** That happens when Vite or Next.js hot-reloads the webview while a Rust IPC call is still in flight: the new page load clears the JavaScript callback registry, so when the Rust side finishes there is no matching handler. It does **not** occur in production bundles where the webview is not hot-reloaded in place; use **`npm run tauri build`** release installers for behavior without this churn. Do not add code to silence this warning in development, since masking it can hide real callback lifecycle bugs.

### Build a release installer

```bash
npm run tauri build
```

Installers are emitted under `src-tauri/target/release/bundle/` (NSIS and MSI targets per `src-tauri/tauri.conf.json`). Tagged releases on GitHub are built by `.github/workflows/release.yml`, which submits artifacts to **SignPath** for signing on behalf of **UXC LLC** (configure organization secrets and IDs as documented in that workflow).

## Project layout

```text
spy-detector/
├── src/                      # Next.js frontend (App Router, static export to `out/`)
├── src/app/                  # Routes and pages
├── src/components/           # Shared UI (charts, settings primitives, shell)
├── src/lib/                  # Hooks, i18n, types, thresholds, utilities
├── src/lib/hooks/            # `useMonitoringTick`, `useScanInterval`, etc.
├── src/lib/i18n/             # Locale catalogs and translation helpers
├── public/                   # Static assets
├── src-tauri/                # Tauri application and Rust crate
├── src-tauri/src/            # IPC commands, detectors, DB, scheduling
├── src-tauri/resources/      # Bundled IOC YAML (`ioc.yaml`, `windows-spy-signatures.yaml`)
├── src-tauri/capabilities/   # Tauri capability allowlists for IPC
└── .github/workflows/        # Release automation (SignPath signing pipeline)
```

### Rust modules you will touch most often

| Module | Role |
| --- | --- |
| `etw_win` | ETW-based process and (when elevated) image-load tracing |
| `etw_win32k` | Win32k ETW (keyboard hooks, clipboard-related signals) |
| `mic_win` | Microphone consent / capability signals via registry |
| `camera_win` | Camera activity via Media Foundation sensor monitor |
| `authenticode` | Binary trust and Authenticode-style checks |
| `beaconing` | Beaconing / jitter heuristics over connection observations |
| `ioc_refresh` | Download and merge refreshed IOC packs from the configured upstream URL |
| `process_actions` | User-confirmed kill / quarantine with audit logging |
| `scheduler` | Periodic full scans and monitoring heartbeat emission |

Other important areas: `commands.rs` (IPC surface), `scan.rs` (batch scan and `Finding` assembly), `monitoring.rs` (tick payload for the UI), `db.rs` (SQLite schema and migrations).

## Development workflow

1. Branch from `main`. Prefer prefixes: `feat/`, `fix/`, `docs/`, `refactor/`, `chore/`.
2. **Conventional Commits** are encouraged: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`.
3. Keep pull requests **small and focused** — one logical change per PR.

### Pre-commit hooks

After `npm install`, Husky installs Git hooks via the `prepare` script. On each commit:

- **lint-staged** runs ESLint with `--max-warnings 0 --fix` on staged `*.ts` / `*.tsx` files.
- **`tsc --noEmit`** runs a full TypeScript check for the frontend.
- If you stage files under `src-tauri/` matching `*.rs` or `Cargo.toml`, **`cargo fmt --check`** and **`cargo clippy`** run for the Tauri crate.
- If you stage anything under `src/`, **`vitest related`** runs (against staged TS/TSX sources) when a `test` npm script is present.

Commit messages are validated against a **Conventional Commits**–style prefix (`feat:`, `fix(scope):`, etc.).

To bypass hooks in an emergency (for example a broken local toolchain), use **`git commit --no-verify`**. Prefer fixing the underlying issue: the same checks run in CI on pushes and pull requests, so skipped hooks can still block merge.

On macOS or Linux, if hooks do not run after clone, ensure the hook scripts are executable: **`chmod +x .husky/post-commit .husky/_post-commit-run.sh`** (Husky’s `npm install` / `prepare` usually sets this automatically on Unix).

### Post-commit checks

After each successful commit, a **non-blocking** background job may run heavier checks so you see failures locally before you **`git push`** (CI will still enforce the same bar). The hook returns immediately; it never rejects or delays the commit.

**What runs (only when matching paths changed in `HEAD`):**

- **`npm test`** (full Vitest run) when any file under **`src/`** was part of the commit.
- **`cargo clippy --all-targets --no-deps -- -D warnings`** and **`cargo test --all`** (from **`src-tauri/`**) when any **`src-tauri/**/*.rs`** or **`src-tauri/**/Cargo.toml`** path changed.

**Logs:** One-line **PASS** / **FAIL** lines per check, plus up to the last **25** lines of output for failures, are appended to **`.git/post-commit.log`** (under the repo’s `.git` directory, not the workspace root).

**Disable temporarily:**

- **`HUSKY=0 git commit ...`** skips Husky hooks (including this **post-commit** script and **pre-commit**).
- **`git commit --no-verify`** skips Git’s **pre-commit** and **commit-msg** hooks only; **`post-commit` still runs** under Git’s rules. To skip the background checks as well, use **`HUSKY=0`** (optionally together with **`--no-verify`**).

Because post-commit is asynchronous, a commit can succeed even if these checks would fail; watch the log or any failure notification (on Windows, a modal may appear from the background worker when something fails).

### Checks to run locally

Before opening a PR, run:

```bash
npm run lint
npx tsc --noEmit
```

From `src-tauri/`:

```bash
cargo check
cargo clippy --all-targets
```

Maintainers expect these to pass in review. Automated workflows today center on release builds; regardless, treat the commands above as the baseline quality gate.

## Adding a new detector

1. Add or extend a module under `src-tauri/src/` (one concern per file when practical).
2. Produce findings consistent with `scan::Finding`: at minimum **`score`**, **`reasons`**, and the usual identifying fields (`pid`, `name`, `exe_path`, etc.). The UI derives **severity tiers** from `score` and user-configured thresholds — you do not need a separate severity field on the struct.
3. Wire the logic into the on-demand scan path via **`commands::run_scan`** → `scan::execute_scan_with_state` / `scan::execute_scan` as appropriate.
4. If the detector runs continuously, follow existing **real-time** patterns (`etw_win`, `etw_win32k`, `camera_win`): start work from the app setup path, gate on **`privilege::is_elevated()`** when admin is required, and expose a **`pub fn is_running() -> bool`** backed by a **`static ... ACTIVE: AtomicBool`** so `monitoring.rs` and the heartbeat stay accurate.
5. Failures in background monitors must **not** crash the app — log, clear the atomic flag, and degrade gracefully.
6. If you add a new **IPC command**, register it in `src-tauri/src/lib.rs`, expose a stable permission slug in `src-tauri/tauri.conf.json` if needed, and add the matching **`allow-...`** entry in **`src-tauri/capabilities/default.json`**.

## Adding a new UI string

1. Add the English source text in **`src/lib/i18n/english.ts`** (splash-only strings may live in `bootstrap.ts` — follow nearby patterns).
2. Consume it with **`useLang()`** from `@/lib/i18nContext` and **`t('your.key')`**.
3. Partial translations are normal: missing locale keys **fall back to English** automatically.
4. For locale-aware dates or numbers, use **`Intl`** APIs with **`useLang().lang`** as the BCP 47 locale tag.

## Adding or refreshing IOC data

- Bundled YAML consumed at compile time lives under **`src-tauri/resources/`** (`ioc.yaml` from the upstream stalkerware-indicators lineage, plus **`windows-spy-signatures.yaml`** for Windows-focused entries). Schema expectations follow **[AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)** conventions where applicable.
- Runtime refresh logic is in **`ioc_refresh.rs`** — update URLs or merge behavior there when pulling from a new upstream.
- If you change catalog metadata surfaced in the UI, update **`IocCatalogBanner`** and related IPC as needed.

## Submitting a pull request

1. Run **lint**, **TypeScript**, **`cargo check`**, and **`cargo clippy`** locally.
2. Describe **motivation**, **approach**, and any **risk / false-positive** considerations for detection changes.
3. For UI changes, attach **screenshots or a short screencast**.
4. Link related issues (`Fixes #123`).
5. All PRs must pass required checks and receive maintainer review before merge.

## Reporting bugs

- **Security-sensitive bugs:** do **not** file a public issue. Follow **[SECURITY.md](./SECURITY.md)**.
- **General defects:** use **GitHub Issues**.
- **Non-security crashes or diagnostics:** you may also use the in-app **Report bug** flow when it helps attach logs the user chooses to send.

## License

By contributing, you agree that your contributions are licensed under the **same MIT terms** as the project. See [LICENSE](./LICENSE) and [NOTICE.md](./NOTICE.md).
