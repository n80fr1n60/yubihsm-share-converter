# SAW maintenance protocol (R13-v2 M8 + security L1)

The operational discipline that surrounds the SAW lane after it flips to
BLOCKING. This file is the table of contents for the policy; see
`saw/README.md` for the user-facing "what does SAW prove" overview and
`.github/workflows/saw-proofs.yml` for the CI lane.

## 1. Soak period record

| Field                                | Value                                   |
|--------------------------------------|-----------------------------------------|
| Date SAW lane first shipped          | 2026-05-12 (R13-B / R13-02 land commit) |
| Date soak period began counting      | 2026-05-12                              |
| Soak end condition                   | EITHER 2 weeks elapsed (2026-05-26) OR  |
|                                      | 5 PRs merged without SAW regressions    |
|                                      | (whichever comes first)                 |
| Soak ended (date / PR / SHA)         | _PENDING_ — flip-to-BLOCKING PR not yet merged |
| Flip-to-BLOCKING PR placeholder      | Will record: PR #___ / commit SHA / maintainer sign-off |

The flip-to-BLOCKING PR removes the `continue-on-error: true` line from
`.github/workflows/saw-proofs.yml` and updates the table above with the
date / PR number / commit SHA / maintainer sign-off. After the flip, the
SAW lane is BLOCKING on push + PR and NON-BLOCKING on cron (see Step 4
below).

## 2. `[skip saw]` label override

Maintainers may attach the `[skip saw]` label to a PR to bypass the SAW
gate. Allowed only for justified non-SAW-related changes (e.g. an
emergency hotfix to non-cryptographic code where SAW's image is
temporarily unreachable). The PR description MUST name the justification
+ cite the SAW-incident-ID under which the bypass is granted. Every
`[skip saw]` usage is logged in the audit-trail table below with date /
PR # / maintainer / justification one-liner.

### Protected paths (R13-v3 cross-finding correctness fix — LOAD-BEARING)

A PR touching ANY of the following files CANNOT bypass the CI SAW gate via
`[skip saw]`. These files contain the production GF kernels that the
CI-safe SAW driver verifies against the Cryptol spec:

* `src/legacy.rs` — `legacy::mul`, `legacy::inv`
* `src/resplit.rs` — `resplit::mul_aes`

Reviewers MUST reject any PR that attaches `[skip saw]` while modifying
`src/legacy.rs` or `src/resplit.rs`. If a PR legitimately must touch one
of these files during a SAW outage, the
correct posture is to PAUSE the PR until the SAW lane is restored
(typically a same-quarter rotation PR per Step 3 below).

### Audit trail

| Date | PR # | Maintainer | Justification |
|------|------|------------|---------------|
| _initial_ | — | — | _no `[skip saw]` invocations yet_ |

## 3. Quarterly toolchain rotation cadence

The SAW Docker image digest + the SAW proof compiler pin are reviewed
every quarter (4× per year). The rotation PR bundles:

* (a) new SAW image sha256 digest, captured via:
  ```bash
  TOKEN=$(curl -s 'https://ghcr.io/token?service=ghcr.io&scope=repository:galoisinc/saw:pull' \
      | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")
  curl -sLI \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      -H "Authorization: Bearer $TOKEN" \
      'https://ghcr.io/v2/galoisinc/saw/manifests/nightly' \
      | grep -i docker-content-digest
  ```
* (b) any intentional Rust proof compiler change. The current CI-safe
  SAW lane is pinned to Rust 1.85 to match the repository MSRV and the
  validated bitcode command.
* (c) `saw/MAINTENANCE.md` rotation-history entry naming the rotation
  date / maintainer / SAW release notes URL.

The rotation cadence is **quarterly** (every 3 months); the rotation
maintainer cross-references the SAW project's release notes for any
LLVM-version or proof-compiler compatibility change that warrants a
sub-quarterly rotation. A rotation that surfaces a SAW counterexample is treated as a
release-blocker per the BLOCKING failure policy — the rotation does NOT
auto-merge with a SAW regression on the table; instead the maintainer
opens an R14 follow-up to investigate the regression before landing the
new pins.

### Rotation history

| Quarter   | Date       | Image digest                                | Proof rustc          | Maintainer | Notes                          |
|-----------|------------|---------------------------------------------|----------------------|------------|--------------------------------|
| Q2 2026   | 2026-05-12 | `sha256:c771f4949415ec0f2c3c4ea54b864a44c9ab7a2b0d822d96998574293552f32f` | `1.85` | R13-B / R13-02 land commit | Initial CI-safe core proof pin; Rust 1.85 matches repository MSRV and the locally validated bitcode command. |

## 4. Cron-side non-blocking posture

The Sunday 07:00 UTC cron run is NON-BLOCKING — toolchain drift between
quarterly rotations cannot spontaneously fail CI on a stable main.
Cron-side failures emit a warning in the workflow log + a notification
to maintainers (via GitHub Actions' "failed workflow" email or a
configured webhook); the next-quarter rotation absorbs the drift.

Mechanism: `continue-on-error: true` is set at the job level during the
soak period, then a follow-up PR per Step 1 above removes that line.
After the flip, the cron-side non-blocking posture is preserved via a
job-level `if: github.event_name != 'schedule'` guard on the `Verify all
llvm_verify directives returned Q.E.D.` step (or equivalent), so the
cron lane logs failures as warnings but does not block downstream
workflows.

## 5. Image-deletion contingency

If the pinned SAW image digest stops resolving on GHCR (image deletion +
re-tag), the Sunday cron lane catches it within a week. Remediation:
maintainer pulls the latest SAW image, captures the new digest per Step
3 (a) above, and ships an emergency rotation PR (steps 1-3 above) even
if it's outside the quarterly cadence. The emergency rotation is
recorded in the table above with the inciting incident referenced.

If the cron also fails to authenticate against GHCR (token outage), the
maintainer escalates to the GHCR-org admin for token reissue; the SAW
lane stays in `continue-on-error: true` posture during the outage and
returns to BLOCKING once the image is reachable again.

## 6. SAW driver maintenance notes

* **`#![no_std]` deviation.** `saw/extracted/lib.rs` is deliberately NOT
  `#![no_std]` (the FIX_PLAN spec listed `#![no_std]` as an optimisation
  for SAW LLVM-IR walks; the implementer DEVIATED to libstd to avoid
  panic-handler boilerplate). If a future SAW image regresses on
  libstd-linked bitcode handling, the rotation PR re-introduces
  `#![no_std]` along with a minimal `#[panic_handler]` that calls
  `core::intrinsics::abort()`.
* **Workspace isolation.** `saw/extracted/Cargo.toml` declares an empty
  `[workspace]` so cargo treats it as a separate workspace root; the
  parent `cargo build --release --locked` does NOT try to build the SAW
  adapter crate. The SAW lane builds it explicitly.
* **Path-dep coupling.** The `yubihsm-share-converter = { path = "../.." }`
  declaration pulls the production kernel bodies into the bitcode
  transitively. A future MSRV bump on the parent crate may require a
  matching bump here (the SAW lane is structurally isolated from the
  main CI build matrix, so the mismatch surfaces at SAW-build time, not
  at parent-cargo-build time).
