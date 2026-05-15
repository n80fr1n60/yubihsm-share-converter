# miri maintenance protocol (R15 v4 — Tree-Borrows soak + Stacked-Borrows BLOCKING)

The operational discipline that surrounds the miri CI lane after the Tree
Borrows leg flips to BLOCKING. This file is the table of contents for
the policy; see `.github/workflows/miri.yml` for the CI lane itself and
`saw/MAINTENANCE.md` for the parallel SAW maintenance protocol that this
document mirrors.

## 1. Soak period record

The Tree Borrows leg of the miri lane ships with `continue-on-error: true`
under the matrix axis (per R15-02 / SD-R15-2), then flips to BLOCKING
once the soak end condition is met. The Stacked Borrows leg is BLOCKING
from R15-02 land-time onward.

| Field                                | Value                                            |
|--------------------------------------|--------------------------------------------------|
| Date Tree Borrows lane first shipped | Tree Borrows lane shipped (R15-02 land date)     |
| Date soak period began counting      | R15-02 land commit (same date)                    |
| Soak end condition                   | EITHER 2 weeks elapsed OR 5 PRs merged without   |
|                                      | Tree-Borrows regressions (whichever comes first) |
| Soak ended (date / PR / SHA)         | _PENDING_ — flip-to-BLOCKING PR not yet merged   |
| Flip-to-BLOCKING PR placeholder      | Will record: PR #___ / commit SHA / maintainer sign-off |

The flip-to-BLOCKING PR removes the `continue-on-error: true` directive
from the Tree Borrows matrix leg in `.github/workflows/miri.yml` and
updates the table above with the flip date / PR number / commit SHA /
maintainer sign-off. After the flip, the miri lane is BLOCKING on push +
PR for both legs.

A Tree-Borrows-regression discovery during soak restarts the soak clock
(mirrors `saw/MAINTENANCE.md §3` rotation-history rationale that a SAW
counterexample during soak does not auto-merge). The 2-weeks-OR-5-PRs
formula is a soak-end CEILING, not a soak-end deadline.

## 2. `[skip miri]` label override policy

Maintainers may attach the `[skip miri]` label to a PR to bypass the
miri gate (both Stacked Borrows and Tree Borrows legs). Allowed only for
justified non-miri-related changes (e.g. an emergency hotfix to a
documentation-only file where miri is temporarily unreachable). The PR
description MUST name the justification + cite the miri-incident-ID
under which the bypass is granted. Every `[skip miri]` usage is logged
in the audit-trail table below with date / PR # / maintainer /
justification one-liner. Mirrors the `[skip saw]` discipline in
`saw/MAINTENANCE.md §2`.

### Protected paths (R15-02 / v2 SF-2 fix — LOAD-BEARING)

A PR touching ANY of the following files CANNOT bypass the CI miri gate
via `[skip miri]`. These files contain the production unsafe blocks +
the secret-material-handling kernels that the miri lane is designed to
catch UB on:

* `src/main.rs` — `lock_down_process` (prctl + setrlimit + getrlimit
  unsafe blocks) + the `check_single_threaded_inner` seam (per v2 fix
  High-1 / Sec SF-2; added in v2 from v1's five-file list).
* `src/secret.rs` — `Secret::with_capacity` (page-aligned alloc +
  `AllocGuard` Drop-on-panic + `libc::madvise` gate per R15-04) + the
  zeroize-on-Drop semantics.
* `src/legacy.rs` — `legacy::mul`, `legacy::inv` GF kernels.
* `src/resplit.rs` — `resplit::mul_aes` GF kernel.
* `src/recover.rs` — Lagrange-recovery kernel + the matrix-rank check.
* `src/parse.rs` — frame-parsing surface (length-bounded reader +
  TLV decoder) that interacts with `Secret<T>` ownership.

Reviewers MUST reject any PR that attaches `[skip miri]` while modifying
any of these six files. If a PR legitimately must touch one of these
files during a miri outage, the correct posture is to PAUSE the PR
until the miri lane is restored (typically a same-quarter rotation PR
per §3 below).

### Audit trail

| Date | PR # | Maintainer | Justification |
|------|------|------------|---------------|
| _initial_ | — | — | _no `[skip miri]` invocations yet_ |

## 2.1 `#[cfg_attr(miri, ignore)]` audit-trail ledger

Per v2 fix Medium-1 / Sec SF-1: every `#[cfg_attr(miri, ignore)]`
introduced on a test (during soak or post-soak) MUST carry an inline
`// MIRI-IGNORE: <rationale> + <ledger-entry-ref>` comment AND a
corresponding row in this ledger table. The ledger entry is a
prerequisite for landing the annotation — reviewers MUST reject any
PR introducing a `#[cfg_attr(miri, ignore)]` without both the inline
comment AND the ledger row. Mirrors the `[skip saw]` audit-trail
discipline per `saw/MAINTENANCE.md §2`.

The discipline activates if (and only if) Tree Borrows surfaces real UB
during soak that cannot be resolved by a production-code refactor (see
§4 divergence handling protocol). The initial state is empty: no test
in the post-R15 baseline currently bears the annotation outside of the
test-call-site cfg gates that R14-03 already documents.

### Ledger

| Date | Test path | Rationale | Expected resolution | Maintainer |
|------|-----------|-----------|---------------------|------------|
| _initial_ | — | — | — | — |

## 3. Quarterly nightly-toolchain rotation cadence

The miri nightly toolchain is reviewed every quarter (4× per year). The
rotation maintainer is the **repository maintainer per CODEOWNERS or
rotation-on-duty** (v2 fix L3 / Sec SF-4: mirrors the
`saw/MAINTENANCE.md §3` rotation-maintainer designation verbatim). The
rotation PR bundles:

* (a) any updated nightly pin (the existing `.github/workflows/miri.yml`
  uses `nightly` unpinned; the rotation reviews whether a named pin like
  `nightly-2026-MM-DD` is needed for a stability reason);
* (b) a clean `cargo +nightly miri test` run against both MIRIFLAGS legs
  (Stacked Borrows default + `-Zmiri-tree-borrows`) executed locally by
  the rotation maintainer before merge;
* (c) any `[skip miri]` label or `#[cfg_attr(miri, ignore)]` review —
  the rotation cycle re-checks every active §2.1 ledger row to confirm
  the "expected resolution" is still on-track and to retire any rows
  whose underlying production-code refactor has landed;
* (d) cross-tool compatibility check vs the `mutants = "0.0.3"` dev-dep
  pin (since cargo-mutants also runs miri-like passes on test mutants;
  the rotation confirms the dev-dep still compiles + runs cleanly under
  the new nightly);
* (e) `docs/MIRI-MAINTENANCE.md` rotation-history entry naming the
  rotation date / maintainer / nightly release notes URL.

The rotation cadence is **quarterly** (every 3 months); the rotation
maintainer cross-references the rust-lang/rust release notes + the miri
project's release notes for any MIRIFLAGS additions, sysroot-rebuild
behavior changes, or borrow-checker model changes that warrant a
sub-quarterly rotation. A rotation that surfaces a miri regression is
treated as a release-blocker per the BLOCKING failure policy — the
rotation does NOT auto-merge with a miri regression on the table;
instead the maintainer opens an R16+ follow-up to investigate the
regression before landing the new pins.

### Rotation history

| Quarter | Date | Nightly pin | Maintainer | Notes |
|---------|------|-------------|------------|-------|
| Q2 2026 | R15-02 land commit | `nightly` (unpinned) | repository maintainer per CODEOWNERS | Initial miri matrix-shape pin: Stacked Borrows BLOCKING + Tree Borrows soak with `continue-on-error: true`; `-Zmiri-tree-borrows` MIRIFLAGS leg added under matrix axis. |

## 3.1 `#[cfg(not(miri))]` gate ledger for production-code call sites

Per the v4 amendment + R15-04 architectural rationale: every
`#[cfg(not(miri))]` annotation added to a **production-code** call site
(NOT a test-only call site; test-only sites follow the §2.1
`#[cfg_attr(miri, ignore)]` ledger discipline) MUST carry an inline
rationale comment ABOVE the gate naming:

1. miri's limitation on the syscall/operation being skipped (with the
   exact "unsupported operation" error string from the miri output);
2. the security property / defense-in-depth role of the gated call;
3. the LOAD-BEARING fall-back controls that remain in place when the
   gated call is skipped (typically process-level controls like H4's
   `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`; the syscall-skipped-under-miri
   site MUST NEVER be the SOLE control for a security property);
4. the miri-coverage goal preserved by the gate (the surrounding Rust
   semantics that miri DOES validate).

AND a corresponding row in the ledger table below. The ledger entry is a
prerequisite for landing the gate — reviewers MUST reject any PR
introducing a production-code `#[cfg(not(miri))]` without both the
inline rationale comment AND the ledger row. Mirrors the `[skip saw]`
audit-trail discipline per `saw/MAINTENANCE.md §2` + the §2.1 ledger
sub-section, but applied to PRODUCTION-CODE call sites instead of test
annotations.

### Ledger

| Date | File:line | Gated syscall/operation | Security property | Load-bearing fall-back | R-round provenance | Maintainer |
|------|-----------|--------------------------|-------------------|------------------------|---------------------|------------|
| 2026-05-14 (R14→R15 boundary) | `src/secret.rs:211` (post-R15-04 placement; the R15-04 implementer landed +32 lines so subsequent line numbers shifted) | `libc::madvise(MADV_DONTDUMP)` | Kernel coredump exclusion of `Secret` bytes (defense-in-depth, per-VMA flag) | H4 process-level controls: `RLIMIT_CORE=0` (via `setrlimit` in `lock_down_process`) + `PR_SET_DUMPABLE=0` (via `prctl` in `lock_down_process`) | R15-04 v4 amendment | repository maintainer per CODEOWNERS |

Future syscall additions land additional rows; the ledger discipline
persists across rounds. The rotation cycle in §3 reviews every active
row to confirm the load-bearing fall-back is still in place and that
miri has not gained native support for the syscall (in which case the
gate retires and the row moves to a "retired" sub-table; not present at
initial creation since no rows are eligible for retirement yet).

## 4. Tree-Borrows-vs-Stacked-Borrows divergence handling protocol

When one aliasing-model lane passes and the other fails, the divergence
is itself a data-point that deserves investigation BEFORE either lane is
disabled (no analogue in `saw/MAINTENANCE.md` because SAW is unary; the
divergence protocol is miri-specific). The protocol:

1. **Investigate first.** Is the difference a real UB the stricter model
   (Tree Borrows) catches that Stacked Borrows misses, or is it
   miri-side over-strictness on the failing model? Inspect the failing
   test's source + the miri trace to triage; consult the miri
   project's known-divergences list + the rust-lang/rust issue tracker
   for the specific UB class.
2. **Refactor production code preferred over `#[cfg_attr(miri, ignore)]`.**
   If the divergence is a real UB, the load-bearing remediation is a
   production-code refactor that eliminates the UB (e.g. replacing a
   `&mut`-aliasing pattern with `UnsafeCell` or with raw-pointer
   discipline). The refactor commit lands as an R16+ item with the
   miri-trace as the inciting evidence.
3. **`#[cfg_attr(miri, ignore)]` with §2.1 ledger entry only after
   architect sign-off.** If the divergence is judged to be miri-side
   over-strictness AND the architect has signed off that the production
   code is correct under the stricter aliasing model, the test may
   carry `#[cfg_attr(miri, ignore)]` with a corresponding §2.1 ledger
   row naming the divergence-investigation outcome + the architect
   sign-off reference. The discipline NEVER disables a lane just to
   make the divergence go away — the load-bearing posture is
   "investigate before disabling" (mirrors the R13-v2 architect-re-review
   High C2 "fail closed" pattern).

### Divergence-investigation log

| Date | Lane | Failing test | Triage outcome | Architect sign-off |
|------|------|--------------|----------------|--------------------|
| _initial_ | — | — | — | — |

Cron-side failure notifications (Tree Borrows leg during soak) are
delivered via GitHub Actions' "failed-workflow email" to maintainers
(same channel as `saw/MAINTENANCE.md §4` uses for SAW cron-side
warnings); the rotation maintainer triages each notification per the
divergence protocol above.

## 5. Image-deletion / nightly-yanked contingency

If the pinned nightly is yanked from rust-lang.org's CDN (the nightly
has been deleted/yanked or rustup's CDN is transiently unreachable),
the miri lane fails at `rustup component add miri --toolchain nightly`
or at `cargo +nightly miri setup`. Remediation:

1. Roll back to the previous quarter's nightly via a named-toolchain
   pin (`nightly-2026-MM-DD` form via `rustup toolchain install
   nightly-2026-MM-DD`) + the `RUSTUP_DIST_SERVER` override if the
   default mirror is also unreachable.
2. Open a rotation PR (per §3 above) even if it falls outside the
   quarterly cadence. The emergency rotation is recorded in §3's
   rotation-history table with the inciting incident referenced.
3. Document the override date + the nightly-yanked regression in the
   rotation-history table.

If the rustup CDN itself is unreachable (DNS / TLS / regional outage),
the miri lane stays in `continue-on-error: true` posture during the
outage and returns to BLOCKING once the CDN is reachable again.
Mirrors `saw/MAINTENANCE.md §5` image-rebuild contingency for the SAW
GHCR image.

## 6. Vendor-bypass `trap` discipline

The miri lane uses a vendor-bypass at `.github/workflows/miri.yml`
to move `.cargo/config.toml` aside before `cargo +nightly miri setup`
(the vendored crate cache in `vendor/` is incompatible with miri's
sysroot rebuild because miri's sysroot links against std crates that
are not in the vendored set). Per v2 fix Medium-2 / Sec SF-7-1 +
Medium-3 / Sec SF-7-2: the bypass uses a **trap-based mktemp-randomized
restore pattern** so a sysroot-build failure cannot leave subsequent
steps resolving against live crates.io (which would defeat the
SLSA-style vendor anchor).

The workflow snippet:

```bash
set -e
BAK="$(mktemp /tmp/.cargo-config.toml.bak.XXXXXX)"
cleanup() {
  if [ -f "$BAK" ]; then
    mv "$BAK" .cargo/config.toml
  fi
}
trap cleanup EXIT
mv .cargo/config.toml "$BAK"
cargo +nightly miri setup
# trap fires at EXIT regardless of exit code
```

Why each piece is load-bearing:

* `mktemp /tmp/.cargo-config.toml.bak.XXXXXX` randomises the backup
  path, eliminating the predictable `/tmp/.cargo-config.toml.bak`
  filename + the co-tenant race window on self-hosted runners.
* `trap cleanup EXIT` guarantees the restore runs whether `miri setup`
  succeeds or fails with a non-zero exit code. The pre-v2 pattern
  (`mv ... && cargo ... && mv ...`) leaves `.cargo/config.toml` at
  the backup path if the middle command fails — defeating the vendor
  anchor for all subsequent steps in the job.
* The `if [ -f "$BAK" ]` guard inside the cleanup handler is idempotent:
  if the restore already ran (e.g. via an explicit final `mv` before
  the trap fires), the cleanup is a no-op.

This pattern is used in `.github/workflows/miri.yml`'s existing miri
lane (post-R15-02). A quarterly rotation per §3 above re-validates the
trap pattern is intact (a refactor to the miri lane that drops the
trap is rejected at review-time as a vendor-anchor regression).
