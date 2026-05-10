# Spy Detector

<!-- badges row: license, build status, platform -->

A Windows desktop application that detects suspicious processes, network behavior, and configuration changes commonly associated with covert surveillance — keylogging, microphone/camera capture, beaconing C2, known stalkerware, and abusive remote-administration tooling.

Spy Detector is a **detection** tool. It does not block, quarantine, or remove processes automatically — the user reviews findings and chooses whether to act.

## Implemented features

### Detection engine

- **Process signatures** — AssoEchap stalkerware IOC catalog plus 30+ Windows-focused entries; matched against name, path, command line.
- **Network IOCs** — live TCP/UDP enumeration via `netstat2`, reverse DNS + DNS-Client ETW for accurate hostname resolution, IOC domain/IP/CIDR matching.
- **Public IP blacklist feeds** — Spamhaus DROP/EDROP, CINS Army, Emerging Threats compromised, Tor exits, FireHOL L1; CIDR support; per-feed enable/refresh.
- **abuse.ch threat intel** — ThreatFox (domains/IPs/URLs/hashes), URLhaus (hosts/URLs), MalwareBazaar hash lookup. Bundled snapshots, manual refresh, no telemetry.
- **Beaconing detection** — inter-arrival jitter analysis on per-`(pid, remote)` connection samples.
- **Process tree anomalies** — curated parent→child rules (e.g. Word spawning PowerShell).
- **Thread injection** — ETW Kernel-Process thread-start events for cross-process thread creation and thread bursts (elevated).
- **Camera / microphone access** — Media Foundation `IMFSensorActivityMonitor` for camera, registry consent store for mic; per-PID activity logging.
- **Keyboard hooks** — ETW `Microsoft-Windows-Win32k` event 1002.
- **Clipboard polling** — ETW Win32k events 459 / 460 / 463 with per-PID counters.
- **Hidden window + network** — `EnumWindows` correlated with active TCP for hidden-UI heuristic.
- **Screen-capture heuristic** — hidden window + unsigned + sustained CPU correlation.
- **Authenticode** — `WinVerifyTrust` signature checks with path-bucket reasoning (signed Microsoft / signed third-party / unsigned / user-writable).
- **Autostart delta** — HKLM / HKCU Run + RunOnce + WOW6432Node, both Startup folders, Task Scheduler logon/boot triggers, with 24h "recently added" tracking.
- **AMSI** — Antimalware Scan Interface provider for script content (PowerShell, VBA, JS, .NET) with suspicious-string heuristics.
- **YARA-X** — bundled APT / Windows malware / stalkerware rule sets, scanning unsigned user-writable binaries.
- **Suspicious developer infrastructure** — bundled IOC list for malicious GitHub repos, paste sites, IPFS gateways, Discord/Telegram CDN, URL shorteners, abused file shares, suspicious URL paths.
- **Browser history scan** — Chrome / Edge / Brave / Firefox history matched against the full IOC catalog (read locally only).

### Management surfaces

- **Startup items** — full enumeration across Run keys, Startup folders, and Task Scheduler with per-item score, signing/IOC reasons, and reversible enable/disable.
- **Services** — Windows Service Control Manager enumeration with score, signing, status, and start/stop + start-type controls. Critical-service denylist enforced in Rust.
- **Browser history surgical delete** — per-row or bulk removal of flagged URLs from the **actual** browser SQLite databases (transactional, bookmarks preserved). Locked-DB detection with running-browser warning + retry banner.
- **Process kill / quarantine** — SHA-256-confirmed actions with PID verification, self-EXE blocking, and audit-logged outcomes.
- **Allowlist + Ignored** — per-process allowlist with display name + reason; "false positive / ignore" flow; dedicated Ignored tab.
- **Per-signature rule editor** — toggle individual signatures, filter by IOC source.

### Realtime + scheduling

- ETW monitoring for process create/exit, image-load injection (elevated), Win32k hooks, clipboard, thread create.
- Periodic background scans, 1 min – 24 h, configurable.
- Periodic browser-history rescans.
- Live activity feed for process launches and thread events with classification (system / signed / unsigned / user-writable).
- Detection components health card on Overview.

### UI / UX

- Tauri 2 + Next.js 16 / React 19 / Tailwind 4 stack, static export.
- Custom dark title bar with elevation pill, process count, ETW status, notifications bell, version chip.
- Native HTML splash screen (no JS framework on the splash window).
- Sticky-column tables (Score / Name pinned left, Actions pinned right) with truncate + hover tooltips and click-to-open detail drawers.
- Cmd+K command palette with fuzzy search and per-action recents.
- Global notification center with toasts, unread bell badge, and native Windows toasts when minimized.
- Sound effects for issue detection and camera/mic access (rate-limited, opt-out, per-event toggles).
- Animated stat cards, severity donut, scan-history sparkline, score gauges.
- Inline kill / quarantine / ignore actions with confirmation modals.

### Local-first

- All scans, findings, and configuration stay under `%APPDATA%\spy-detector\` — SQLite, audit log, settings.
- No telemetry, no cloud sync, no analytics. External feeds are explicitly opt-in with manual refresh.
- Run on boot is opt-in via Settings or system tray.

### Audit + reporting

- Unified event log (10k-row ring buffer) covering camera, mic, hook, clipboard, process launch, thread injection, autostart delta, AMSI, YARA, abuse.ch, kill, quarantine, browser-history removal, service / autostart toggles.
- Filterable + searchable in-app log viewer with severity chips and clear-logs control.
- Bug reporter with diagnostics bundle (commit SHA, build date, target, log tail).
- Export latest scan as JSON or Markdown.

### Translations

- 25 supported locales. 8 priority locales (en-US, hy-AM, ar, de, es, fr, ru, zh-CN) at 100% coverage with RTL support. See [Translations](#translations) for details.

### Operations

- IOC catalog auto-refresh with ETag / If-Modified-Since headers.
- Bundled YARA, IP feeds, and abuse.ch snapshots refreshable independently.
- Optional UAC elevation on demand via "Restart as administrator".
- System tray with close-to-tray, foreground/restore, and quit.
- Localized first-run language picker + Terms acceptance flow.

## Known issues

- **Occasional UI freeze on menu changes.** Navigating between pages (e.g. Allowlist → Startup → Services) sometimes briefly hangs the window. Root cause is not yet pinpointed; suspected long IPC contention with the on-launch scan, ETW initialization races, or webview layout thrash on heavy table mounts. Workarounds: wait a few seconds, or quit and relaunch (the second launch is typically fine because caches are warm). To help us diagnose, enable **Settings → Advanced → Diagnostic logging**, reproduce the freeze, then send `%APPDATA%\spy-detector\app.log` via **Report bug**. See [DEBUGGING.md](./DEBUGGING.md) for attaching a debugger.
- **Limited mode without elevation.** Several detectors (Process / Win32k / DNS ETW, image-load injection heuristic) are inactive when the app runs without administrator privileges. Use **Restart as administrator** from the elevation banner for full coverage.
- **Microsoft Defender / EDR can exhaust ETW sessions.** On systems with many ETW consumers, the kernel session pool can fill up and our subscriptions return *"Insufficient system resources"*. Auto-cleanup of stale `spy-detector-*` sessions runs at startup; if the issue persists, reboot or close other ETW consumers (Process Monitor, Wireshark with NPM, etc.).
- **AMSI provider not registered.** The provider DLL must be Authenticode-signed to be loaded by Windows. Until SignPath enrollment is complete, AMSI shows **Inactive** even when elevated.
- **First-launch table latency.** The first cold launch after install can stall briefly while caches warm; subsequent launches respond within ~1s. The splash screen now waits on real backend readiness signals before showing the main window, but very slow disks may still see a longer initial wait.

## Planned

- **Open-source code signing** — finalize SignPath Foundation enrollment for signed MSI / NSIS releases under the **UXC LLC** publisher, removing Windows SmartScreen warnings on direct downloads.
- **MCP server for AI agents** — expose detection results, scan controls, allowlist, and audit log over a local [Model Context Protocol](https://modelcontextprotocol.io/) server so LLM-powered agents (Claude Desktop, Cursor, etc.) can investigate hosts read-only or perform supervised remediation. Tools planned include `list_findings`, `scan_now`, `inspect_process`, `read_event_log`, `lookup_ioc`, and (gated) `kill_process` / `disable_autostart`. Local-only, opt-in, with the same SHA-256-confirmed action gating used today.

## Translations

The interface is fully translated where coverage is 100%; lower-coverage locales fall back to English for any missing keys. Help us improve coverage by opening a PR — see [CONTRIBUTING.md](./CONTRIBUTING.md#adding-a-new-ui-string).

| Language | Code | Coverage |
| --- | --- | --- |
| English (United States) | `en-US` | 100% |
| Հայերեն | `hy-AM` | 100% |
| العربية | `ar` | 100% |
| Deutsch | `de` | 100% |
| Español | `es` | 100% |
| Français | `fr` | 100% |
| Русский | `ru` | 100% |
| 简体中文 | `zh-CN` | 100% |
| English (United Kingdom) | `en-GB` | 5% |
| Português (Brasil) | `pt-BR` | 2% |
| Italiano | `it` | 2% |
| 日本語 | `ja` | 2% |
| Nederlands | `nl` | 2% |
| Polski | `pl` | 2% |
| Türkçe | `tr` | 2% |
| Українська | `uk` | 2% |
| فارسی | `fa` | 1% |
| עברית | `he` | 1% |
| Bahasa Indonesia | `id` | 1% |
| 한국어 | `ko` | 1% |
| Tiếng Việt | `vi` | 1% |
| 繁體中文 | `zh-TW` | 1% |
| हिन्दी | `hi` | 1% |
| বাংলা | `bn` | 1% |
| ไทย | `th` | 1% |

_Coverage measured against 667 total UI strings as of 2026-05-09._

## Architecture

- **Shell:** Tauri 2 (Rust backend, Next.js 16 + React 19 frontend served as static export).
- **Backend:** Rust crate at `src-tauri/`. Detection engine over `sysinfo`, `netstat2`, `ferrisetw`, `windows-rs` (Media Foundation, WinTrust, registry).
- **Frontend:** Next.js App Router with Tailwind 4, framer-motion, recharts, lucide-react.
- **Storage:** SQLite at `%APPDATA%\spy-detector\db.sqlite`.

## Detection vectors

| Signal | Implementation |
|---|---|
| Stalkerware signatures | AssoEchap IOC YAML + 30+ Windows-focused entries |
| Network IOCs | TCP/UDP enumeration → reverse DNS + DNS-Client ETW → IOC index lookup |
| IP blacklist feeds | Spamhaus DROP/EDROP, CINS Army, ET compromised, Tor exits, FireHOL L1 (CIDR) |
| abuse.ch threat intel | ThreatFox, URLhaus, MalwareBazaar hash lookup |
| Microphone | HKCU CapabilityAccessManager registry consent store |
| Camera | Media Foundation `IMFSensorActivityMonitor` |
| Keyboard hooks | ETW `Microsoft-Windows-Win32k`, event 1002 |
| Clipboard polling | Win32k events 459/460/463 |
| Process tree anomalies | Curated parent→child rules |
| Thread injection | ETW Kernel-Process thread-start cross-process detection (elevated) |
| Beaconing | Inter-arrival jitter analysis |
| Unsigned binary | `WinVerifyTrust` + path checks |
| Hidden window + network | `EnumWindows` + active TCP |
| Autostart delta | HKLM/HKCU Run + RunOnce + WOW6432Node + Startup folders + Task Scheduler |
| Suspicious DLL loads | ETW Kernel-Process image-load (elevated) |
| Screen capture (heuristic) | hidden + unsigned + sustained CPU |
| AMSI | Antimalware Scan Interface provider with script-content heuristics |
| YARA-X | Bundled APT / Windows malware / stalkerware rules on user-writable binaries |
| Dev-infra abuse | Malicious GitHub, paste sites, IPFS, Discord/Telegram CDN, shorteners |
| Browser history | Chrome/Edge/Brave/Firefox history matched against the full IOC catalog |

## Privacy

All scans, findings, and configuration stay local. Spy Detector does not send telemetry, upload scan results, or transmit personal data. See [NOTICE.md](./NOTICE.md) for the full disclaimer.

## Building from source

Prerequisites: Node.js 20+, Rust stable, Windows 10/11.

```sh
git clone git@github.com:UXCentury/spy-detector.git
cd spy-detector
npm install
npm run tauri dev
```

For a production build:

```sh
npm run tauri build
```

The MSI/NSIS installers land in `src-tauri/target/release/bundle/`.

## Releases

Production releases are built by GitHub Actions and signed via [SignPath Foundation](https://signpath.org/foundation). Direct builds from this repository may trigger Windows SmartScreen warnings until reputation accumulates.

## Publisher

Released and signed by **UXC LLC** (uxcentury.com).

## License

[MIT License](./LICENSE) © 2026 Spy Detector Authors.

Credits for third-party assets: see [NOTICE.md](./NOTICE.md).

## Contributing

Issues and pull requests welcome. Please ensure new detection signals include rationale, false-positive considerations, and (where possible) tests. Read [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, layout, and PR expectations. For scope and limits of detection, see [THREAT_MODEL.md](./THREAT_MODEL.md); for benign software that can look suspicious, see [FALSE_POSITIVES.md](./FALSE_POSITIVES.md). Community interactions follow the [Code of Conduct](./CODE_OF_CONDUCT.md); report security issues per [SECURITY.md](./SECURITY.md); match house style with [CODING_GUIDELINES.md](./CODING_GUIDELINES.md).

## Acknowledgments

- [AssoEchap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) — primary IOC source.
- [SignPath Foundation](https://signpath.org/foundation) — code signing for OSS.
- [Tauri](https://tauri.app/), [Next.js](https://nextjs.org/), [Rust](https://rust-lang.org/).
