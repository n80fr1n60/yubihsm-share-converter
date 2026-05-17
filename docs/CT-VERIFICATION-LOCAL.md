# Local CT verification — R24 v3 LOCAL-ONLY

This document covers the LOAD-BEARING local constant-time (CT) verification
surface added in R24 v3. It is the maintainer-runnable counterpart to the
existing CI lanes; the wrapper script `scripts/run-ct-local.sh` is the
forensic anchor for every release tag.

## Why local-only?

Two distinct CT-verification gaps surfaced after R23:

1. **Post-R22-supersede empirical timing gap.** R22 planned a `dudect-bencher`
   harness; the crate's transitive deps include `clap 2.34` → unsound `atty`
   (RUSTSEC-2021-0145) which fails `cargo audit --deny warnings`. R22 was
   SUPERSEDED in tree, leaving the empirical real-CPU timing lane EMPTY
   (R23 cachegrind is a simulator, not a CPU).

2. **Post-R23 honest-evaluation adversarial-input-coverage gap.** R23
   cachegrind shipped 5 input classes per kernel
   (Zero/One/AllOnes/Canonical/Sample). The honest evaluation noted this is
   adequate for internal-review-grade CT claims but is NOT adversarial —
   there's no Hamming-weight sweep, no reduction-boundary trigger, and the
   "Sample" class is a fixed byte literal not a real sample.

R24 closes both gaps with two new lanes:

- **R24-01** — a hand-rolled minimal dudect harness (Welch's t-test +
  paper-§3.2 percentile cropping; Reparaz et al. 2017) in
  `benches/dudect_kernels.rs`. NO `dudect-bencher` dev-dep; depends only on
  stdlib + the existing `rand 0.8`. `Cargo.lock` is byte-identical
  pre/post-R24.

- **R24-02** — a 16-variant `InputClass` enum in `benches/cachegrind_kernels.rs`
  covering 9 Hamming weights (HW0..HW8) + 2 reduction-boundary triggers
  (REDB1, REDB7) + canonical FIPS-197 anchor + 4 off-diagonal asymmetric
  classes (OFFD1..OFFD4). 312 pairwise diffs on x86_64.

Per the maintainer's v3 scope adjustment, **NO new CI/CD workflow files are
added**; the existing R23 `cachegrind.yml` workflow stays UNCHANGED at its
5-class matrix. The 16-class superset + the dudect lane are exercised
LOCALLY by the maintainer-runnable wrapper script.

## The two lanes

| Lane                | Tool                                | Surface in v3                            |
|---------------------|-------------------------------------|------------------------------------------|
| Cachegrind 16-class | `valgrind --tool=cachegrind`        | `benches/cachegrind_kernels.rs`          |
| Hand-rolled dudect  | `std::time::Instant` + Welch's t    | `benches/dudect_kernels.rs`              |

Cachegrind is a deterministic simulator — counter delta = real bug, not flaky
test. Dudect is a statistical test on wall-clock samples — `|t| < 10` per
the dudect paper §5.1 tri-zone interpretation (`<5` no-leak / `5..10`
indeterminate / `>=10` leak).

## How to run

```sh
# Run cachegrind only (~12-19 min on x86_64).
./scripts/run-ct-local.sh cachegrind

# Run dudect only (~10-15 min; 5 sub-cases × 5 runs = 25 measurements).
./scripts/run-ct-local.sh dudect

# Run both sequentially (~22-34 min total).
./scripts/run-ct-local.sh all

# Print the usage banner.
./scripts/run-ct-local.sh --help
```

Logfiles are written to `/tmp/ct-local-{subcommand}-<timestamp>.log` so the
maintainer can review even on a failing run. The wrapper emits a one-line
PASS summary on stdout suitable for pasting into release notes:

```
PASS: scripts/run-ct-local.sh cachegrind (312 diffs, zero counter delta)
PASS: scripts/run-ct-local.sh dudect (25 measurements, MAX|t|=<x> < 10)
```

## Prerequisites

- **Rust stable toolchain** at the project's MSRV (1.85 per `Cargo.toml`)
  pinned in the project's `.cargo/config.toml` chain.
- **valgrind >= 3.18** for the cachegrind subcommand. On Debian/Ubuntu:
  `sudo apt-get install valgrind`. The wrapper exits with code 3 + a clear
  message if valgrind is missing.
- **bash + awk + grep + diff** (standard Unix toolchain).

The dudect subcommand does NOT require valgrind.

## Expected wall-clock budget

Per FIX_PLAN.html #r24-acceptance (v3 LOCAL-ONLY):

- **Cachegrind**: 50 cells × ~10-15 sec/cell ≈ 8-13 min for the cachegrind
  invocations + ~3-5 min for the 312 pairwise diffs + ~30-60 sec aggregate
  startup ≈ **~12-19 min** total on x86_64 (~3 GHz, 4 cores).
- **Dudect**: 5 sub-cases × ~5-6 sec/measurement loop × 5 runs ≈
  **~10-15 min** (the wrapper amortises the build cost across all 25
  measurements; the per-measurement wall-clock is dominated by the
  `SAMPLES = 100_000` × `INNER_BATCH = 1000` kernel-call loops).

Slower hosts (laptop CPUs, virtualised cores) may take ~30 min for `all`.

## Acceptance gates (v4 amendment — path (c))

Per FIX_PLAN.html `#r24-v4-amendment` (architect + security joint review;
maintainer-locked path (c)):

**LOAD-BEARING (release-blocking) gates** — the wrapper EXITs NON-ZERO on:

- **Cachegrind**: any pairwise diff yields non-zero kernel-row counter
  delta. The diff message identifies the (kernel, class_a, class_b) cell
  and prints the actual counter delta for triage. 312/312 pairwise diffs
  zero counter delta on x86_64 = PASS.
- **Dudect sample_split_gate**: any sub-case yields `|L - R| / (L + R) > 5%`
  (defence-in-depth against a silently-broken `rng.gen::<bool>()` floor;
  v2 Amendment 7 reframed for v3). The form-guard regression test at
  `tests/dudect_harness_form.rs` locks the harness's randomisation
  invariants reactively; the sample-split gate is the proactive complement.
- **Dudect harness-internal errors**: NaN/inf t-statistic, parse failure,
  empty harness output.

**ADVISORY (informational, NOT release-blocking) gate**:

- **Dudect MAX |t|**: any of the 25 measurements yielding |t| ≥ 10 across
  the 5 percentile cuts is reported as an ADVISORY transient. The wrapper
  prints the offending (run, sub-case) cell + the MAX |t| value + the
  per-sub-case transient counts but EXITs 0 regardless. Rationale: dudect
  wall-clock timing on a typical maintainer host (no CPU pinning, no
  CT-laboratory tuning) is host-noise-sensitive at the |t| ≥ 10 threshold;
  the 0.95 percentile cut in particular admits asymmetric-tail-cropping
  artifacts on the mul sub-cases. Cachegrind's deterministic counter-diff
  + KernelDisass.html's instruction-level proof together are the LOAD-
  BEARING CT discharge; dudect provides a real-CPU complementary signal
  that flags suspicious patterns for manual investigation but does not
  block release on transient noise.
- **R22 v2 Amendment 4 escalation ladder** (manual investigation
  procedure): if the SAME sub-case shows |t| ≥ 10 on 5 out of 5 consecutive
  runs, that is a REAL CT leak signal and an R-FIX round must address the
  production-code timing bug BEFORE the next release. 1-4 of 5 same-sub-
  case ≥ 10 transients are classified as host noise per the ladder.

On success: exit 0 + one-line ADVISORY / ADVISORY-with-transients summary
on stdout. Cachegrind: one-line PASS summary on stdout (LOAD-BEARING).

## Release discipline

Per FIX_PLAN.html #r24-v3-changelog Amendment G (NEW v3 contract):

> The maintainer runs `./scripts/run-ct-local.sh all` **BEFORE staging the
> R24 commit AND BEFORE tagging every release**; the wrapper's one-line
> PASS summary is the forensic anchor pasted into release notes. A failed
> wrapper invocation **BLOCKS the release tag** (manual contract; not
> git-hook-automated).

This is a release-discipline contract; not a push-time CI gate. Push-time
CI continues to exercise the R23 5-class subset cachegrind matrix
(unchanged) + the `tests/dudect_harness_form.rs` regression test (the only
new CI-side gate for R24, runs under the existing `ci.yml` cargo-test
invocation).

## Escalation ladder (`|t| ≥ 10` or non-zero counter delta)

Per FIX_PLAN.html #r22-v2-changelog Amendment 4 + #r24-acceptance v3:

1. **Re-run on the same local host with the same seed**. The deterministic
   seed `DUDECT_RNG_SEED = 0x756e6963_6f72_6e75` makes the run
   reproducible. A `|t| ≥ 10` on a single noisy sample MAY be a runner-side
   tail outlier; the 5× re-run amortises this.

2. **If 5 of 5 re-runs report `|t| ≥ 10` on the same sub-case**: this is a
   REAL production-code timing bug. Surface it as a separate R24-FIX round
   to fix the production code BEFORE the R24 commit lands. Do NOT modify
   the harness to suppress the signal.

3. **If cachegrind reports a non-zero counter delta**: this is deterministic,
   not statistical — re-run is not load-bearing. Investigate the offending
   (kernel, class_a, class_b) cell + the actual counter delta. A non-zero
   delta indicates a data-dependent instruction-stream or memory-access
   pattern in the kernel; a REAL CT violation.

## Microarchitectural side-channel residue

Per FIX_PLAN.html #r24-acceptance residue posture (v2 Amendment 6):

The R24 local discharge surface covers cache-replay-level + wall-clock-level
CT verification. It does NOT cover the following microarchitectural side
channels (each tracked-for-R25+ but the post-R24 CT claim is honest about
the bounded scope):

- Speculative execution leaks (Spectre v1/v2/v4, MDS, RIDL)
- Power analysis (DPA, SPA, RAPL-channel)
- DRAM rowhammer (co-tenancy bit-flip)
- SMT cache-contention (HyperThreading-sibling LLC sampling)
- DVFS-induced timing (CPU frequency scaling)

A future R-round may add a perf-counter sampling lane to cover some of
these; for R24 the surface is bounded to deterministic-CT (cachegrind) +
empirical-wall-clock-CT (dudect) over a 16-class adversarial-input space
on x86_64.

## Cross-references

- `KernelDisass.html` — instruction-level CT proof (the R22-SUPERSEDED-era
  static analysis anchor). The 3 GF(2^8) production kernels show 0 `jcc`,
  0 `cmov-on-secret`, 0 operand-indexed memory access at the disassembly
  level. R24's empirical discharge complements this static evidence.
- `.github/workflows/cachegrind.yml` — the R23 CI lane at its 5-class
  matrix subset (BYTE-IDENTICAL pre/post-R24 in v3). CI exercises the
  5-class subset on push/PR + Sunday 06:00 UTC cron; the wrapper script
  exercises the 16-class superset locally at release time.
- `docs/CRYPTO-SPEC.md` — the kernel-level CT properties + the Cryptol
  spec anchors `mul_aes(0x57, 0x83) == 0xC1`, `inv_aes(0x53) == 0xCA`,
  etc., that the empirical discharge verifies indirectly.
- `docs/THREAT-MODEL.md` — the broader side-channel threat model + the
  v3 LOCAL-ONLY release-discipline rationale.
- `FIX_PLAN.html#r24-plan`, `#r24-01`, `#r24-02`, `#r24-acceptance`,
  `#r24-v3-changelog`, `#r24-lock-v3` — the load-bearing plan sections
  for R24.

## Source-form regression test

The form discipline of `benches/dudect_kernels.rs` is locked by
`tests/dudect_harness_form.rs` which runs under `cargo test --release
--locked` as part of the existing `ci.yml` test invocation. It is the only
NEW CI-side gate for R24. The 12+ grep-style assertions defend against
refactors that would silently weaken the harness — e.g. removing the
randomised `rng.gen::<bool>()` class selection, dropping the `black_box`
wraps, or reverting to the SUPERSEDED `dudect_bencher` crate.

See FIX_PLAN.html #r24-01 for the full assertion list + the underlying
Amendment 9 + R22 v3 source-form-guard precedent.
