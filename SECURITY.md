# Security Policy

## Supported Versions

This project follows a release-based support model. Security fixes are
applied to the latest tagged release on `main`. Pre-release / development
branches are NOT considered supported for security purposes.

| Version                | Supported  |
| ---------------------- | ---------- |
| latest tagged release  | yes        |
| prior tagged releases  | no         |
| main branch (untagged) | best-effort |

## Reporting a Vulnerability

**Please do NOT file a public GitHub Issue for security vulnerabilities.**
Issues are publicly visible and would disclose the vulnerability
prematurely.

Instead, report security issues through **GitHub Security Advisories**
using GitHub's **Private Vulnerability Reporting** channel:

1. Navigate to the repository's **Security** tab on github.com (the
   per-repo Security tab — for this repo:
   `https://github.com/<owner>/yubihsm-share-converter/security`).
2. Click **Report a vulnerability**.
3. Fill in the advisory form. Provide a short description, reproduction
   steps, and (if possible) a suggested mitigation. Attach a proof-of-
   concept only if it can be shared safely.

This creates a private advisory visible only to the maintainers and the
reporter. The maintainer monitors that channel. GitHub's
[Private Vulnerability Reporting documentation][gh-pvr] covers the full
workflow.

There is **no email reporting channel** for this project. All security
correspondence happens inside the Private Vulnerability Reporting
advisory thread, so that the audit trail (timestamps, reviewer changes,
remediation status) is captured by GitHub for future disclosure.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

### Maintainer setup (one-shot)

Private Vulnerability Reporting must be **enabled** in the repository
before reporters can use the Security tab to file. The maintainer must,
once per repository:

1. Open the repository on github.com.
2. Navigate to **Settings → Code security and analysis** (this section
   is sometimes labelled **Security & analysis** in older UIs).
3. Find **Private vulnerability reporting** and click **Enable**.

Until this is done, the Security tab will not show the "Report a
vulnerability" button and reporters will have no documented channel.
This is the only manual prerequisite for this policy to be reachable
end-to-end.

## Disclosure Policy

We follow a **90-day coordinated disclosure** window from the date a
report is acknowledged:

- **Day 0**: report received via Private Vulnerability Reporting. We
  acknowledge receipt within 7 days.
- **Day 30**: a draft fix or workaround is shared with the reporter
  inside the advisory thread for confirmation.
- **Day 60**: a release candidate addressing the issue is prepared.
- **Day 90**: public disclosure via GitHub Security Advisory, with
  credit to the reporter (opt-in) and a CVE if the maintainer / reporter
  judge one to be appropriate.

CVE issuance is handled via the GitHub Advisory pipeline (GitHub is a
CNA). The reporter and maintainer agree on whether to request a CVE
when the advisory is drafted.

If a vulnerability is actively exploited in the wild, we may shorten
the 90-day window — likely to an immediate fix-and-release. If a fix
requires upstream coordination (for example, a YubiHSM firmware change),
we may extend the window with the reporter's agreement.

Coordinated disclosure is preferred. We do not threaten or otherwise
discourage research; reporters who go public before the disclosure
window closes will still receive an advisory credit if the report was
valid, though the coordinated-disclosure benefit (advance notice for
downstream consumers) is then lost.

## Scope

In scope:
- The Rust converter binary (`src/main.rs`, `src/legacy.rs`,
  `src/resplit.rs`, `src/secret.rs`).
- The ceremony shell scripts (`scripts/*.sh`) and the Python pexpect
  driver (`scripts/drive_manager.py`).
- The CI / release workflows under `.github/workflows/`.

Out of scope (see [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the
full list and rationale):

- **SLSA build provenance and binary signing.** Per maintainer
  directive, neither is in scope for this project.
- **Vulnerabilities in the YubiHSM firmware or `yubihsm-manager`
  upstream.** Please report those to Yubico directly.
- **Vulnerabilities in the Rust toolchain or transitive dependencies.**
  Please report those to the respective upstream maintainers
  (rust-lang/rust, crates.io maintainers).
- **Side-channel attacks against physical YubiHSM hardware or against
  the physical ceremony host** (cold-boot, EM emanation, power
  analysis). These require hardware-level countermeasures outside the
  converter's scope.
- **Kernel exploits or root-level adversaries on the ceremony host.**
  The threat model assumes the host is dedicated and not actively
  compromised at the kernel level.
- **Operational issues** (operator mistakes following the runbook, host
  misconfiguration that violates the assumptions in
  `docs/THREAT-MODEL.md` §1). Please file a regular Issue or PR.

## Acknowledgements

We publicly thank reporters who follow this policy. Credit is opt-in;
we will ask the reporter before naming them in any advisory.
