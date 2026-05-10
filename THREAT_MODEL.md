# Threat model

This document describes what Spy Detector is designed to observe, what classes of attacker it can and cannot address, and where trust boundaries sit. It complements the legal disclaimer in [NOTICE.md](./NOTICE.md) and the coordinated disclosure process in [SECURITY.md](./SECURITY.md). For day-to-day benign noise and how to ignore or tune findings, see [FALSE_POSITIVES.md](./FALSE_POSITIVES.md).

## 1. Purpose

Spy Detector is a **detection** application aimed at covert surveillance tooling and stalkerware patterns on Windows desktops. It correlates process metadata, network endpoints, autostart surfaces, script interfaces, media-device signals, and curated indicator feeds so an operator can **see** what might be monitoring them. It is **not** a kernel-mode antivirus, enterprise EDR, or anti-rootkit product: it does not install a filter driver, inject callbacks into the kernel security stack, or guarantee real-time blocking of malicious actions before they occur.

All evaluation happens **on the endpoint**, inside the Spy Detector process and its subprocesses (including the embedded WebView2 host). Scan results, logs, and configuration are stored locally; **no telemetry or scan payloads are transmitted** unless the user explicitly triggers network actions (for example refreshing IOC feeds or submitting a bug report composed in the UI).

Spy Detector differs from several adjacent categories:

- **Antivirus / EDR** — Typically relies on kernel drivers, minifilters, file-system callbacks, and central policy to block or remediate in real time across the fleet.
- **Host intrusion prevention (HIPS)** — Actively intervenes on suspicious API sequences or policy violations at runtime.
- **Forensic triage agents** — Tools such as KAPE or Velociraptor collectors prioritize artifact sweep and incident workflows across many hosts; Spy Detector is an interactive local console focused on surveillance-adjacent signals and stalkerware IOCs.

Because detections are synthesized locally, **operator judgment** remains central: scores aggregate signals that may be benign in context (see [FALSE_POSITIVES.md](./FALSE_POSITIVES.md)). The app does not silently remediate; [NOTICE.md](./NOTICE.md) states that mutations occur only after explicit user confirmation.

## 2. Assets we're protecting

- **Keystrokes, microphone audio, camera frames, screen content, clipboard text** — High-value user data commonly targeted by spyware; many detectors flag access patterns or hooks correlated with capture.
- **Browser history and session-adjacent state (indirectly)** — History scanning surfaces URLs matching IOC catalogs; it does not extract stored passwords by design, but URLs can imply credential-phishing or remote-admin landing pages.
- **Local network endpoints** — Connections that imply remote desktop, sync, or command-and-control toward the user’s own infrastructure or an adversary’s relays.
- **Autonomy and situational awareness** — The operator’s ability to know **what is running**, **what persists**, and **what is talking on the network** without trusting an opaque cloud verdict.

Protecting these assets does **not** imply Spy Detector can guarantee confidentiality against every attacker; it improves **visibility** for classes of abuse that leave observable user-mode footprints.

## 3. Adversaries / threat actors considered

Rows marked **Partial** or **Out of scope** are not “ignored because we dislike them”—they reflect architectural limits (no kernel agent, no hardware introspection, no packet decryption). Partial coverage still helps (for example historical IOC URLs in browser databases) but must not be mistaken for browser-extension sandbox inspection or kernel integrity enforcement.

| Adversary | Capability | In scope? |
| --- | --- | --- |
| Commercial stalkerware vendors | User-mode installers with admin once; persistence via Run keys, Startup, scheduled tasks | **Yes** |
| Abusive RMM tooling (TeamViewer, AnyDesk, RustDesk, etc., used coercively) | Legitimate signed binaries, network beacons, tray-only or hidden UI | **Yes** |
| Generic infostealers using LOLBins | PowerShell, `mshta`, `rundll32` reaching IOC hosts or suspicious infrastructure | **Yes** |
| Browser-resident malicious extensions | Extension IDs / URLs less visible; visited IOC URLs in history may surface | **Partial** |
| Driver-level / kernel rootkits (SSDT hooks, PatchGuard bypass class) | Cloak ETW, hide processes, subvert user-mode visibility | **Out of scope** |
| Firmware / BIOS implants (UEFI, SMM) | Pre-OS persistence | **Out of scope** |
| Hardware keyloggers and physical interposers | USB shim, inline capture hardware | **Out of scope** |
| Network-only attackers without local foothold | MITM, DNS poisoning of upstream feeds | **Out of scope** |
| Nation-state with custom kernel implant | Defeats user-mode-only observation by design | **Out of scope** |

**Feed integrity note:** Network adversaries without a local foothold cannot directly read your SQLite store, but they could theoretically interfere with **IOC downloads** if DNS or TLS interception were controlled—another reason refresh actions are manual and should run on networks you trust.

## 4. Detection surfaces and their guarantees

Honest limits matter more than marketing claims. Each surface below states what we **can** rely on and what we **cannot**.

### Process enumeration (`sysinfo`)

- **Can:** List user-mode processes visible to the current token with paths and arguments where the OS exposes them.
- **Cannot:** See processes hidden via deliberate manipulation of user-mode structures (for example PEB / VAD tricks used by sophisticated malware). Cannot enumerate kernel-only code paths as first-class “processes.”

### Network enumeration (`netstat2`, TCP/UDP)

- **Can:** Match the same connection rows the OS exposes for established sockets; correlate remote IPs and ports with IOC catalogs and public IP feeds.
- **Cannot:** Observe traffic that bypasses normal TCP/IP stack accounting (raw sockets used in exotic ways, passive sniffers in another stack position). Cannot see encrypted payload semantics without decrypting TLS.

Reverse DNS and passive resolver hints may **mis-resolve** transient CDN nodes; combine hostname evidence with process attribution and timeline context.

### Process tree anomaly rules

- **Can:** Flag curated parent→child pairs that malware droppers often exhibit (for example productivity binaries spawning scripting hosts).
- **Cannot:** Prove malicious intent—IT automation, installers, and developer tooling routinely spawn the same children.

### Beaconing and jitter heuristics

- **Can:** Highlight remote endpoints whose connection timing looks like low-jitter beacons compared to interactive browsing.
- **Cannot:** Distinguish intentional keep-alives (chat clients, sync, monitoring agents) from malicious C2 without additional corroboration.

### Hidden window correlated with active TCP

- **Can:** Combine `EnumWindows` visibility hints with live sockets to spotlight tray-only or intentionally minimized network programs—common in stalkerware and unwanted RMM persistence.
- **Cannot:** Prove stealth intent; many legitimate agents minimize UI while maintaining tunnels.

### Screen-capture heuristic

- **Can:** Raise suspicion when hidden-window, unsigned, and sustained CPU patterns align with desktop-grabbing malware archetypes.
- **Cannot:** Confirm framebuffer access; games, video transcoders, and GPU utilities may resemble the same resource profile.

### Cross-process thread creation (Kernel-Process ETW)

- **Can:** When elevated, observe thread-start events that originate from another process—useful for classic injection patterns.
- **Cannot:** Attribute motive; software protectors, game anti-cheat, and debugging tools also inject threads.

### DLL load paths (image-load ETW)

- **Can:** When elevated, record unusual image loads (for example modules pulled from user-writable paths) that pair well with signature and Authenticode context.
- **Cannot:** See loads suppressed by kernel hiding techniques; cannot validate semantic behavior of each DLL.

### Autostart and Task Scheduler enumeration

- **Can:** Diff Run keys, Startup folders, and logon/boot tasks to spotlight freshly persisted binaries.
- **Cannot:** Catch persistence that lives purely in another user profile without scanning that profile, or firmware-resident implants.

### Developer-infrastructure URL and path IOCs

- **Can:** Match browsing history and network indicators against curated lists of abused paste sites, repo patterns, shorteners, and similar abuse lanes.
- **Cannot:** Tell whether **your** visit was benign research versus adversary delivery—context matters (see false-positive guidance).

### ETW (Kernel-Process, Win32k, DNS-Client)

- **Can:** Tie together provider-specific traces—process create/exit lifecycles, Win32k keyboard-hook and clipboard-related events (session-scoped), and DNS-Client trails that refine hostname attribution beyond static `netstat` snapshots. Dedicated headings above call out cross-process thread creation and suspicious image loads when elevation unlocks those keywords.
- **Cannot:** Without elevation, kernel-backed keywords needed for some injection narratives stay unavailable. Win32k visibility does not cross interactive sessions. Highly privileged malware may tamper with tracing configuration; Spy Detector does **not** detect ETW suppression or provider muting by itself.

### Authenticode (`WinVerifyTrust`)

- **Can:** Classify binaries as signed (Microsoft, third-party) or unsigned relative to the machine’s trust store and path heuristics (for example user-writable directories).
- **Cannot:** Detect a compromised enterprise root or malicious additions to the trusted CA store; stolen-but-valid certificates produce **false negatives** for “unsigned / untrusted” style reasoning.

### Media Foundation (`IMFSensorActivityMonitor`)

- **Can:** Surface camera activity for many modern apps that route through Microsoft’s Media Foundation pipeline.
- **Cannot:** Guarantee visibility for software that talks directly to alternate stacks (legacy DirectShow-only paths or bespoke drivers) without MF involvement.

### Microphone consent registry (`CapabilityAccessManager`)

- **Can:** Read the per-user consent database the OS maintains for Modern-capability mic access.
- **Cannot:** Reflect apps running as `SYSTEM` that ignore the consent store, or vendors that bypass documented consent surfaces entirely.

### AMSI

- **Can:** Inspect script content submitted by AMSI-aware hosts (PowerShell, JScript, VBScript, .NET 4.8+) when those hosts participate.
- **Cannot:** See purely native implants, shellcode, or hosts that never call AMSI; Office macros depend on host integration paths.

### YARA-X

- **Can:** Scan file paths with bundled rulesets; focuses on **unsigned, user-writable** binaries to reduce noise.
- **Cannot:** Flag malware signed with a trusted certificate; **process-memory scanning** may be expanded later but is not the primary guarantee today.

### IOC catalogs

- **Can:** Match processes, paths, domains, IPs, and URLs against bundled YAML (including [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)), abuse.ch snapshots ([ThreatFox](https://threatfox.abuse.ch/), [URLhaus](https://urlhaus.abuse.ch/)), optional MalwareBazaar hash lookups, and curated lists (developer-infrastructure abuse, downloadable IP deny/feeds).
- **Cannot:** Invent novel indicators; freshness depends on **manual refresh** and bundled snapshots—stale data yields **false negatives**. Upstream labeling mistakes propagate unless reporters notify maintainers ([FALSE_POSITIVES.md § upstream](./FALSE_POSITIVES.md#what-to-do-when-you-see-a-false-positive)).

### Browser history scan

- **Can:** Read local SQLite history stores for supported browsers and match URLs against the same IOC index used elsewhere.
- **Cannot:** Recover history that was never written (strict private browsing), wiped, or stored in profiles Spy Detector does not open.

### Process actions (kill, quarantine, autostart toggle, service stop, browser close)

All mutations run **as the Spy Detector process subject to Windows ACLs**:

- **`kill_process`** / **`quarantine_process`** — Require a SHA-256 **confirm token** derived from a prefix (`KILL` / `QUARANTINE`), numeric PID, and the executable path string (see `process_actions::confirm_token_hex`). The UI must fetch a fresh token after rescans because PID reuse would otherwise create ambiguity; Rust verifies the live image path still matches recent findings when possible. Termination uses `OpenProcess`/`TerminateProcess`. Failures surface as structured errors (often elevation-related). Self-termination and self-quarantine are refused.
- **`set_startup_entry_enabled`** — HKLM-wide and machine scheduled tasks generally require administrator rights; HKCU and per-user Startup folder entries may not.
- **`set_service_enabled`** / start-type changes — Require elevation for SCM mutations. A **critical-service denylist** in Rust blocks disabling core OS services (including `WinDefend`, `MpsSvc`, `EventLog`, RPC endpoints, `Schedule`, `BFE`, `LanmanServer`, `LSM`, `gpsvc`, `Dhcp`, `Dnscache`, `LanmanWorkstation`) even if the UI were abused.
- **`delete_browser_history_findings`** — Executes transactional `DELETE`s against live browser databases when safe; does not upload history.
- **`close_browser_safely_cmd`** — Posts `WM_CLOSE` to top-level browser windows, optionally escalating to `TerminateProcess` when forced.

Outcomes for security-sensitive actions are written to the **unified audit event log** (ring buffer in-app) with severity and structured detail.

## 5. Trust boundaries

- **User session boundary** — The Tauri backend and Next.js static UI run in the interactive user session. Effective privilege equals the token under which the operator launched the app (standard user vs. elevated administrator via UAC).
- **WebView2** — Hosts the UI in Chromium-derived sandboxed renderer processes. Data crosses into Rust **only** through Tauri’s typed IPC surface; the shipped bundle does not load arbitrary remote origins for application logic.
- **Tauri capability allowlist** — `src-tauri/capabilities/default.json` enumerates each allowed IPC permission (`allow-kill-process`, `allow-quarantine-process`, etc.). Commands not granted there are unreachable from the frontend even if defined in Rust.
- **External network** — Egress is limited to **explicit user intent**: refreshing IOC packs, optional IP feeds and abuse.ch snapshots, MalwareBazaar hash lookup, and **manual** bug-report submission. There is no background analytics beacon.
- **Disk** — Runtime state lives under `%APPDATA%\spy-detector\` (SQLite database, rolling logs, quarantine folder, IOC cache). The installer places binaries under Program Files; Spy Detector does not require writing under `%PROGRAMFILES%` during normal scans.

IPC payloads are structured JSON; the UI cannot invoke arbitrary Rust functions or fetch remote modules at runtime. From a threat-model perspective, compromise of the frontend implies attacker-controlled **invocation of already-exposed commands**, not arbitrary code execution inside the sandbox—still serious (kill/quarantine toggles) but bounded by command implementations and capability gates.

Operators should treat `%APPDATA%\spy-detector\db.sqlite` as **sensitive**: it holds findings analogous to a defensive scan report. Disk encryption and workstation hygiene remain important independent controls.

Anyone with administrator rights on the PC can copy, modify, or delete that database—Spy Detector does **not** implement offline tamper-evidence or remote attestation. Treat unexpected score resets or missing historical findings as potentially suspicious in high-threat scenarios.

## 6. Privilege model

- **Release builds** embed `requireAdministrator` in `src-tauri/windows/app.release.manifest` so first-run detection sees elevated-capable ETW providers where the OS permits.
- **Development builds** use `asInvoker` (`src-tauri/windows/app.manifest`) so `tauri dev` does not prompt UAC on every reload; operators restart elevated when testing kernel-backed traces.
- **Graceful degradation** — Detectors that require privilege consult `privilege::is_process_elevated()` (and related helpers). Limited modes emit log lines and UI affordances rather than failing silently.
- **Mutating IPC** — Commands such as `kill_process`, `quarantine_process`, `set_service_enabled`, `set_startup_entry_enabled`, `delete_browser_history_findings`, and `close_browser_safely_cmd` enforce OS-realistic checks and return explicit errors when the token lacks rights.

When degradation applies, the Overview **detection health** affordances and textual logs should state which subsystem is restricted—silent omission of entire detector classes is avoided by design.

The table below is a **rule-of-thumb**—Windows ACLs on protected processes (services, elevated installers, anti-tamper hooks) may still refuse termination even when Spy Detector itself is elevated.

| IPC command | Why privilege matters |
| --- | --- |
| `kill_process` | Requires `PROCESS_TERMINATE` rights on the target; protected processes and cross-session handles may fail without matching elevation |
| `quarantine_process` | Needs permission to move the on-disk image before termination; locked files mirror kill semantics |
| `set_service_enabled` / `set_service_start_type` | Service Control Manager mutations require administrator token except edge cases |
| `set_startup_entry_enabled` | HKLM Run keys and machine-wide scheduled tasks require elevation; HKCU entries typically do not |
| `delete_browser_history_findings` | Needs read/write access to the browser profile databases; browsers lock files while running |
| `close_browser_safely_cmd` | Posts window messages first; forced termination overlaps with `kill_process` privilege story |

## 7. Data handling and privacy

- **Local-first** — Scan outputs persist in `%APPDATA%\spy-detector\db.sqlite` and companion logs. Operators can clear data from Settings → Privacy.
- **No ambient telemetry** — No crash-report pipeline unless the user opens the bug reporter and sends content they composed.
- **Browser history** — Read locally for matching; removal actions mutate only the relevant rows while preserving bookmarks and unrelated tables where applicable.
- **Bug reports** — Bundles include metadata such as commit SHA, build date, target triple, and log tail **chosen for export** by the user.

Quarantine moves executables into `%APPDATA%\spy-detector\quarantine\` with timestamps; operators should monitor disk usage and delete archived binaries when investigations conclude.

## 8. Supply-chain considerations

- **Release signing** — Production installers are intended to be signed via **SignPath Foundation** under **UXC LLC**; enrollment status is summarized as “Planned” in [README.md](./README.md). Unsigned artifacts warrant higher SmartScreen friction.
- **IOC bundles** — YAML and abuse.ch snapshots ship at build time; runtime refresh requires user action and uses conditional requests where supported (`ioc_refresh.rs`).
- **Dependency review** — Lockfiles pin npm and Cargo versions; upgrades deserve maintainer review especially for crates wrapping Win32 APIs.
- **CI** — [`.github/workflows/checks.yml`](./.github/workflows/checks.yml) runs ESLint, TypeScript checks, frontend tests, `cargo fmt`, `cargo clippy`, and `cargo test`. Run **`npm audit`** and **`cargo audit`** locally when bumping dependencies; promoting them into CI is tracked work.
- **Frontend bundle** — The exported Next.js assets ship inside the installer; compromising the build pipeline could lace static files. Release workflows should remain branch-protected with mandatory review, matching expectations for any desktop software.

Third-party IOC YAML retains upstream licensing constraints documented beside those repositories; Spy Detector redistributes curated snapshots but does not claim ownership of indicator intellectual property.

## 9. Known limitations

- No detection for kernel rootkits, firmware implants, or hardware intercepts.
- No syscall blocking or kernel prevention plane—**detection and optional user-triggered remediation**, not autonomous blocking like AV minifilters.
- An **admin-equivalent adversary** who compromises the box before Spy Detector runs can tamper with databases, terminate the app, or disable tracing; Spy Detector does not pretend to be tamper-proof without driver-backed enforcement.
- AMSI, YARA-X, and IP feeds are **helpers**—false negatives remain likely when malware avoids those surfaces or presents as trusted code.
- IOC snapshots age; press **Refresh IOC** (and related feed controls) before high-stakes reviews.
- **Browser extensions** are not scanned as first-class install artifacts; malicious extensions may leave sparse history signals compared to native implants.
- **Encrypted containers** and nested VMs inside the workstation hide activity from host-side process enumeration the same way they hide from most user-mode tools.
- **Legitimate dual-use tools** (pentest frameworks, remote admin, parental-control suites) remain ambiguous—consent and proportionality are not encoded as booleans.

## Appendix: Operational assumptions

These assumptions are not guarantees—they clarify where the model **stops**:

- **Baseline workstation integrity** — Spy Detector assumes the OS loader, WinTrust store, and ETW infrastructure are intact enough for observations to mean something. A kernel implant that lies to user-mode APIs defeats every consumer-grade detector.
- **Trusted operator at keyboard** — Physical adversaries who can enter credentials or attach debugging hardware bypass software controls.
- **Manual refresh discipline** — IOC freshness is bounded by user-triggered downloads; automated enterprise distribution of refreshed feeds is out of scope for this document.
- **Single administrative tenant** — Shared PCs with mutually untrusted admins are harder than the common single-user home scenario; findings may reflect prior sessions’ persistence.

### Monitoring cadence expectations

Realtime ETW feeds and periodic scans consume CPU and disk I/O proportional to machine churn. Extremely busy developer workstations may produce larger event volumes than lightly used laptops; this affects **log retention** and human review time, not fundamental guarantees. Operators should align scan intervals with tolerance for brief CPU spikes (configured under Settings).

When laptops sleep, connection-oriented beaconing statistics necessarily pause—resume drift is expected rather than evidence of tampering.

## 10. Out-of-band reporting

Report security defects affecting confidentiality, integrity, or privilege boundaries through the **private** channels documented in [SECURITY.md](./SECURITY.md) (GitHub Security Advisories or `security@uxcentury.com`). Do **not** rely on this threat-model section for timelines or scope judgments—follow the policy there verbatim.

Examples that belong in that pipeline rather than public issues include: bypass of the confirm-token gate, capability allowlist mistakes exposing unintended IPC, filesystem path traversal inside quarantine or log export, deserialization flaws turning IPC JSON into memory corruption, and trust-store manipulation that weakens Authenticode conclusions across the app.

## Contributing detectors

New signals should document their assumptions and false-positive posture. See [CONTRIBUTING.md § Adding a new detector](./CONTRIBUTING.md#adding-a-new-detector).

### Implementation map (non-exhaustive)

| Concern | Primary Rust modules / files |
| --- | --- |
| Process / scan orchestration | `scan.rs`, `commands.rs` |
| ETW session lifecycle | `etw_win.rs`, `etw_win32k.rs` |
| Device sensors | `camera_win.rs`, `mic_win.rs` |
| Trust + signing | `authenticode.rs` |
| Networking + beaconing | `netstat2`, `beaconing.rs` |
| IOC merge / refresh | `ioc.rs`, `ioc_refresh.rs` |
| Actions + auditing | `process_actions.rs`, `browser_close.rs`, `services.rs`, `event_log.rs` |
| Persistence enumeration | Startup / Task Scheduler plumbing via `commands.rs` |
