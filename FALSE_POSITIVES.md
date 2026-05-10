# False positives

Spy Detector prioritizes surfacing **anything that might explain unwanted surveillance**. That stance inevitably overlaps legitimate software. This guide explains **why** benign programs sometimes alarm, gives **concrete examples** per detector family, and describes **what to do** without encouraging reckless dismissal.

Technical limits of each detector live under [section 4](./THREAT_MODEL.md#4-detection-surfaces-and-their-guarantees) in [THREAT_MODEL.md](./THREAT_MODEL.md). Legal limits and “no automatic blocking” language appear in [NOTICE.md](./NOTICE.md).

## Why false positives happen

Detection combines **heuristics** (process trees, hidden UI vs. active sockets, beaconing statistics, consent/registry signals, unsigned paths) with **signature-style** matches (IOC names, domains, IPs, YARA rules). Heuristics codify behaviors that malware often exhibits—but legitimate vendors ship updates, agents, and accessibility aids that reuse the same mechanics. Signature feeds inherit upstream labeling noise and CDN collisions.

Scores aggregate independent reasons; a single noisy signal does not equal conviction. Conversely, absence of a signal does not prove safety—especially when malware deliberately avoids AMSI, hides from ETW, or presents as signed.

Neither layer proves malicious intent on its own. Spy Detector exposes context so **you** decide whether coercive surveillance is plausible in your situation.

## Common false positives by detector

### Process tree anomalies

- Microsoft Office spawning **PowerShell** during automation or legacy macros (rarer today but still seen).
- **Power Automate Desktop** or IT scripts launched from productivity suites.
- Chromium-based browsers spawning **update helpers** or crash reporters.
- **IDEs** (Visual Studio Code, JetBrains) spawning dozens of language servers, git helpers, and indexers during startup.

### Hidden window plus network

- **Cloud sync** agents (Dropbox, OneDrive, Google Drive) maintaining idle HTTPS tunnels with tray-only UI.
- **Remote support** tools (AnyDesk, TeamViewer, RustDesk) keeping beacon sockets while minimizing visible windows.
- **Discord**, **Slack**, or chat clients in tray-only mode.
- **Password-manager** background agents (1Password, Bitwarden) that hide main UI until invoked.

### Unsigned binary heuristics

- **PortableApps** distributions and unzip-to-run utilities without Authenticode budgets.
- Locally compiled **developer tools**, debug binaries, and CI artifacts copied to user-writable folders.
- **GitHub Releases** assets from small maintainers who do not purchase certificates.
- Binaries retrieved via **`nightly.link`** or similar CI artifact bridges—unsigned but authentic.
- **Python virtualenvs**, **Node `node_modules/.bin` shims**, and **Rust `target/release`** drops executing directly from writeable trees—the Authenticode “unsigned + user-writable” pairing triggers by design.

### Beaconing pattern analysis

- Legitimate **telemetry heartbeats** (browser sync, IDE analytics opt-ins, gaming clients such as Steam).
- **WebSocket** integrations (Slack, Discord bots, Notion sync) with steady reconnect intervals.
- **Self-hosted CI runners** polling GitHub or GitLab APIs.

### Microphone access signals

- Videoconferencing (**Zoom**, **Teams**, **Google Meet**, **Slack huddles**, **Discord** voice).
- **Dictation** features in browsers or Windows speech assistants.
- Hardware vendor **mic test** utilities shipping with laptops.

### Camera access signals

- **Windows Hello** infrared / webcam enrollment flows.
- Conferencing apps and **OBS Studio** virtual camera setups.
- OEM **camera control** utilities.

### Keyboard hooks (Win32k ETW)

- **Text expanders** (Espanso) and personal **AutoHotkey** scripts.
- **Accessibility** helpers that remap keys or provide on-screen keyboards.
- **Clipboard managers** that listen globally for copy events (often implemented with hook-adjacent plumbing).

### Clipboard polling

- **Clipboard history** tools (Ditto, ClipboardFusion).
- **Password managers** briefly inspecting clipboard after a copy for OTP or password workflows.
- **Translation** overlays and screenshot annotators reacting to clipboard changes.

### Autostart entries

- **Docker Desktop**, **JetBrains Toolbox**, **Figma** agents, and other developer glue that insists on starting at logon.
- **VPN clients**, **corporate MDM enrollments**, and **Wi-Fi management utilities** that reinstall helpers after feature updates.
- **Microsoft Teams**, **Zoom**, and webinar installers registering background agents even when you seldom open the main UI.
- **Game overlays** (NVIDIA GeForce Experience, Steam).
- Peripheral suites (**Logitech Options**, **Razer Synapse**, **Corsair iCUE**) registering helpers.

Scheduled tasks deserve the same patience as Run keys—Windows ships dozens of maintenance tasks; third-party tasks whose authors chose ambiguous names may resemble malware persistence until you open Task Scheduler and read the command line.

### Suspicious DLL loads (elevated image-load ETW)

- Applications legitimately loading DLLs from **`%LOCALAPPDATA%`** (Electron apps such as Discord, Slack, Spotify, Teams cache native modules there).

### IP / domain IOCs

- **Shared CDN fronts** (Cloudflare, Fastly, CloudFront) where one abusive hostname historically mapped to an IP still serving thousands of benign sites—feeds may lag behind reality.

### Stalkerware signature names

- **MDM**, **parental-control**, and **family-sharing** titles sometimes share installation footprints or indicator names with abusive stalkerware. Consent and proportionality are social/legal questions; Spy Detector flags technical similarity so you can investigate context.

### AMSI script heuristics

- **DevOps PowerShell** using `Invoke-WebRequest`, `Invoke-Expression`, or Base64 blobs for legitimate automation—patterns overlap commodity malware droppers.

### YARA-X matches on user-writable binaries

- Intentionally present **pen-test tooling** (Metasploit-related artifacts, credential tooling in lab VMs, certain Sysinternals forks repackaged unsigned).

### Browser history developer-infrastructure hits

- Visiting your **own GitHub fork**, internal **paste bins**, **IPFS gateways**, or URL shorteners used during CI demos—IOC lists track abuse patterns, not your intent.

### Screen-capture-style CPU + hidden-window heuristic

- **Fullscreen games** and **GPU miners** sometimes minimize UI while consuming sustained CPU—similar silhouette to unwanted grabbers until you read the process identity.
- **Video transcoders**, **Blender renders**, and **live-streaming prep** tools running headless workers.
- **Folded chat apps** during presentations—hidden main window yet active GPU/CPU workers.

### Cross-process thread injection alerts

- **Anti-cheat**, **DRM**, and **software protectors** injecting threads into games or media players.
- **Debuggers** and **profiler shims** attached by developers during local troubleshooting.

### Process name / path IOC collisions

- Utilities renamed to match upstream YAML tokens inside malware repositories during research.
- Generic executable names (`update.exe`, `service.exe`) shared by dozens of unrelated publishers—always validate **path**, **signature**, and **parent process**.

### Reverse DNS and hostname mismatches

- CDNs that rotate PTR records slower than edge routing—your browser may hit a benign property while the PTR still mentions an old abusive hostname.
- Corporate **split-horizon DNS** returning different answers than public resolvers, producing confusing cross-checks—trust local IT context when applicable.

## What to do when you see a false positive

1. Open the row and read the **drawer** text—combined reasons matter more than the headline score.
2. Capture whether the program was **expected** (you installed it) versus **surprising** (you never authorized remote administration software).
3. If you trust the program, mark it **ignored / false positive** so it moves to the **Ignored** tab and stops influencing the aggregate score.
4. Optionally attach a **note** documenting why you dismissed it (helpful when revisiting months later).
5. For chronic noise from one signature, open **Settings → Detection → Rules** and disable that specific signature while leaving others enabled.
6. For upstream IOC mistakes, report to the feed owner:
   - [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
   - [abuse.ch ThreatFox](https://threatfox.abuse.ch/) / [URLhaus](https://urlhaus.abuse.ch/) via their published reporting flows
7. If the detector logic itself feels wrong for most users, open a **`feature_request`** issue describing the benign workflow—not only the binary name.

## How to report a false positive (to Spy Detector)

- File an issue using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
- Include: detector name, **full drawer text**, affected binary path or URL, signing status, and **why you believe the finding is benign**.
- Do **not** paste secrets, cookies, passwords, or unrelated browsing history.
- Maintainers will **never** ask you to upload suspicious binaries in public issues; if a sample is genuinely required, instructions will come through a controlled channel referenced from [SECURITY.md](./SECURITY.md).

## Allowlist vs. ignore vs. disable rule

| Action | Scope | Use when |
| --- | --- | --- |
| **Ignore (mark FP)** | One finding ID | You trust this exact process instance or URL today |
| **Allowlist by path** | Future findings for the same image path | The binary is expected on your machine across reinstalls |
| **Disable signature in Rules** | That signature everywhere locally | The rule is systematically too noisy for your environment |

## When not to dismiss

If you are **unsure** and face elevated personal risk—**domestic violence contexts**, **journalism**, **activism**, or **high-threat enterprise roles**—treating unfamiliar entries as “noise” can be dangerous. Coercive partners and stalkers intentionally pick tools that look legitimate (consumer RMM, parental apps). When in doubt, pause before clicking **Ignore**, photograph or export the drawer text out-of-band, and talk to someone who handles tech-enabled abuse routinely.

Consult specialist support:

- [Coalition Against Stalkerware](https://stopstalkerware.org/)
- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)

For vulnerabilities or suspected exploitation of Spy Detector itself, follow [SECURITY.md](./SECURITY.md) instead of public issues.
