# Security policy

## Reporting a vulnerability

**Do not** open a public GitHub issue for unfixed security problems.

Please report using **one** of these channels:

1. GitHub **Security Advisories**: use **Report a vulnerability** on this repository (private submission).
2. Email **`security@uxcentury.com`**.

### What to include

- Steps to reproduce, or a concise proof-of-concept when safe to share.
- Affected **version or commit**, and **platform** (Windows build, architecture).
- **Impact** assessment (confidentiality, integrity, availability, privilege boundaries).

### Timeline

- Maintainers will **acknowledge** receipt within **5 business days** when contact details are valid.
- We aim for **coordinated disclosure** with a **90-day** maximum embargo, or sooner when a fix is released — whichever comes first.

## Scope

**In scope** for coordinated disclosure includes vulnerabilities in:

- Detection logic that can be abused to mislead users or hide malicious activity
- Privilege handling and elevation boundaries
- IPC commands and capability enforcement
- Process **kill** / **quarantine** flows and their confirmation mechanisms
- **Auto-update** and installer integrity assumptions shipped by this project

**Out of scope** (report elsewhere or as ordinary bugs):

- Third-party services, upstream packages, or OS components outside our control
- Misconfiguration by end users or organizational policy gaps
- Pure usability issues without a security impact (use regular issues unless sensitive)

## Hall of fame

Security researchers who report valid issues and wish to be credited may be named in **release notes** or advisories. Say whether you want attribution when you report.

## Policy compatibility

General defect reports that are **not** security-sensitive belong in **GitHub Issues**. See [CONTRIBUTING.md](./CONTRIBUTING.md) for workflow.
