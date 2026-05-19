# Local CT verification — R24 v3 + R25-01 LOCAL-ONLY

This document covers the LOAD-BEARING local constant-time (CT) verification
surface added in R24 v3 and extended in R25-01 with TIMECOP-style memcheck-
taint. It is the maintainer-runnable counterpart to the existing CI lanes;
the wrapper script `scripts/run-ct-local.sh` is the forensic anchor for
every release tag.

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

## The three lanes (R25-01 expansion)

| Lane                | Tool                                                  | Surface                            | Posture                |
|---------------------|-------------------------------------------------------|------------------------------------|------------------------|
| Cachegrind 16-class | `valgrind --tool=cachegrind`                          | `benches/cachegrind_kernels.rs`    | LOAD-BEARING           |
| Hand-rolled dudect  | `std::time::Instant` + Welch's t                      | `benches/dudect_kernels.rs`        | ADVISORY (R24 v4)      |
| Memcheck-taint      | `valgrind --tool=memcheck` + `VALGRIND_MAKE_MEM_UNDEFINED` | `benches/memcheck_kernels.rs` | LOAD-BEARING (SD-R25-5) |

Cachegrind is a deterministic simulator — counter delta = real bug, not flaky
test. Dudect is a statistical test on wall-clock samples — `|t| < 10` per
the dudect paper §5.1 tri-zone interpretation (`<5` no-leak / `5..10`
indeterminate / `>=10` leak). Memcheck-taint is a deterministic per-byte
dataflow tracker — any branch / address / store dependent on tainted secret
bytes triggers a warning pointing to the EXACT source line; canonical
Bernstein/SUPERCOP convention (codified as TIMECOP; same technique
BoringSSL + libsodium use). The four-axis CT-verification chain (source-form
+ cachegrind + dudect + KernelDisass.html) becomes a FIVE-axis chain with
R25-01.

### LOAD-BEARING summary (3 LOAD-BEARING + 1 ADVISORY)

| Axis                                  | Posture                | Wrapper exit on failure       |
|---------------------------------------|------------------------|-------------------------------|
| Cachegrind 312/312 zero counter delta | LOAD-BEARING (R24 v4)  | exit 1                        |
| KernelDisass.html instruction-stream  | LOAD-BEARING (R24 v4)  | manual review (one-shot)      |
| Memcheck-taint zero warnings          | LOAD-BEARING (R25-01)  | exit 1                        |
| Dudect MAX `|t|`                      | ADVISORY (R24 v4 path c) | exit 0 ALWAYS                 |

## How to run

```sh
# Run cachegrind only (~12-19 min on x86_64).
./scripts/run-ct-local.sh cachegrind

# Run dudect only (~40-60 min; 5 sub-cases × 20 runs = 100 measurements).
./scripts/run-ct-local.sh dudect

# Run memcheck-taint only (R25-01; ~2-5 min; 5 sub-cases × N=3 = 15 invocations).
./scripts/run-ct-local.sh memcheck

# Run all three sequentially (~45-75 min total).
./scripts/run-ct-local.sh all

# Print the usage banner.
./scripts/run-ct-local.sh --help
```

Logfiles are written to `/tmp/ct-local-{subcommand}-<timestamp>.log` so the
maintainer can review even on a failing run. The wrapper emits one-line
summaries on stdout suitable for pasting into release notes (v4 amendment
path (c) at `FIX_PLAN.html#r24-v4-amendment` — cachegrind is the
LOAD-BEARING release-blocking gate; dudect is ADVISORY-only):

```
PASS:     scripts/run-ct-local.sh cachegrind (312 diffs, zero counter delta)
ADVISORY: scripts/run-ct-local.sh dudect (100 measurements; overall MAX|t|=<x>;
          cachegrind 312/312 zero delta is the LOAD-BEARING gate per v4 amendment)
```

On a noisy host the dudect summary becomes `ADVISORY-with-transients: ...
(<n>/100 transient(s) |t|>=10; overall MAX|t|=<x>; per-sub-case fail counts
logged above; cachegrind + KernelDisass.html are the LOAD-BEARING gates)` —
still exit 0 always (wrapper exits 0 ALWAYS per R26 v4 path (c) ADVISORY-only
contract preservation; the R22 v2 Amendment 4 5-consecutive-runs ladder remains
MANUAL investigation procedure — if 5/5 same-sub-case ≥10 appears in any of
the 16 sliding-window positions across the 20 runs, the maintainer escalates
to a separate R-FIX round per the manual contract).

## Prerequisites

- **Rust stable toolchain** at the project's MSRV (1.85 per `Cargo.toml`)
  pinned in the project's `.cargo/config.toml` chain.
- **valgrind >= 3.18** for the cachegrind subcommand. On Debian/Ubuntu:
  `sudo apt-get install valgrind`. The wrapper exits with code 3 + a clear
  message if valgrind is missing.
- **bash + awk + grep + diff** (standard Unix toolchain).

The dudect subcommand does NOT require valgrind.

## Expected wall-clock budget

Per FIX_PLAN.html #r24-acceptance (v3 LOCAL-ONLY) + #r26-plan + #r26-03
(R26 post-uplift baseline) + #r25-plan (R25-01 memcheck-taint extension):

- **Cachegrind**: 50 cells × ~10-15 sec/cell ≈ 8-13 min for the cachegrind
  invocations + ~3-5 min for the 312 pairwise diffs + ~30-60 sec aggregate
  startup ≈ **~12-19 min** total on x86_64 (~3 GHz, 4 cores). UNCHANGED by
  R26 (the cachegrind subcommand is byte-identical pre/post-R26 per SD-R26-3).
- **Dudect**: 5 sub-cases × ~25-30 sec/measurement loop × 20 runs ≈
  **~40-60 min** on a 5×-faster maintainer host (R26 v2 wall-clock note); up
  to **~2 hr** on a reference-class 4-core ~3 GHz host. The per-measurement
  wall-clock is dominated by the `SAMPLES = 1_000_000` (R26-02 uplift from
  100_000) × `INNER_BATCH = 1000` kernel-call loops; the R26-03 outer-loop
  uplift (5 → 20 runs) gives the wrapper 100 total measurements (5 × 20) =
  4× the pre-R26 denominator for the maintainer's MANUAL escalation-ladder
  pattern-spotting across 16 sliding-window positions.
- **Memcheck-taint (R25-01)**: 5 sub-cases × N=3 = 15 invocations × ~30-50×
  memcheck overhead × sub-millisecond native kernel cost ≈ **~2-5 min** on
  x86_64. Per MEDIUM-3 BINARY-signal clarification: memcheck-taint detects
  on a SINGLE execution; N=3 is for fail-loud robustness against transient
  PRNG-state effects, NOT a SAMPLES sweep.

Slower hosts (laptop CPUs, virtualised cores) may take ~2 hr for `all` in
the R26 post-uplift regime. The conservative ~2 hr table estimate from the
R26 plan is the upper bound; ~30-60 min is realistic on a maintainer host
that is 5×-faster than the reference class. R25-01 adds ~2-5 min to `all`.

The dudect lane is ADVISORY-only per R24 v4 amendment path (c) and
maintainer-locked HIGH-1 (a) preservation in R26 — the wrapper exits 0
ALWAYS, regardless of transient observations across the 100 measurements.

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

- **Dudect MAX |t|**: any of the 100 measurements (R26-03 uplift; 5 sub-cases
  × 20 runs) yielding |t| ≥ 10 across the 5 percentile cuts is reported as
  an ADVISORY transient. The wrapper prints the offending (run, sub-case)
  cell + the MAX |t| value + the per-sub-case transient counts but EXITs 0
  regardless. Rationale: dudect wall-clock timing on a typical maintainer
  host (R26-01 last-core CPU pinning + nice -n -10 applied as probe-then-
  invoke ADVISORY-only mitigations; no CT-laboratory tuning) is host-noise-
  sensitive at the |t| ≥ 10 threshold; the 0.95 percentile cut in particular
  admits asymmetric-tail-cropping artifacts on the mul sub-cases.
  Cachegrind's deterministic counter-diff + KernelDisass.html's instruction-
  level proof together are the LOAD-BEARING CT discharge; dudect provides a
  real-CPU complementary signal that flags suspicious patterns for manual
  investigation but does not block release on transient noise.
- **R22 v2 Amendment 4 escalation ladder** (MANUAL investigation procedure;
  R26-03 preserves the absolute 5-consecutive-runs threshold — NOT
  relativized to 25% — per SD-R26-7 + maintainer-locked HIGH-1 (a)): if the
  SAME sub-case shows |t| ≥ 10 on 5 consecutive runs in any of the 16
  sliding-window positions across the 20 runs (runs 1-5, 2-6, ..., 16-20),
  that is a REAL CT leak signal and a separate R-FIX round must address the
  production-code timing bug BEFORE the next release. 0-4 of 5 same-sub-
  case ≥ 10 transients in any sliding window are classified as host noise
  per the ladder. The wrapper does NOT contain a programmatic 5-consecutive-
  runs sliding-window scanner — the 20-run regime simply gives the maintainer
  16 sliding-window positions to scan in the per-(run, sub-case) transient
  forensic output emitted at the bottom of `run_dudect()`. The wrapper exits
  0 ALWAYS on the dudect lane (ADVISORY-only contract per R24 v4 path (c)
  preservation in R26).

On success: exit 0 + one-line ADVISORY / ADVISORY-with-transients summary
on stdout. Cachegrind: one-line PASS summary on stdout (LOAD-BEARING).

## memcheck-taint (R25-01 LOAD-BEARING)

R25-01 adds the canonical Bernstein/SUPERCOP dynamic-taint axis — same
technique BoringSSL and libsodium use, codified as TIMECOP. The harness at
`benches/memcheck_kernels.rs` marks each kernel's secret-bearing input
bytes as "undefined" via the `VALGRIND_MAKE_MEM_UNDEFINED` valgrind client
request (hand-rolled inline-asm FFI macro per SD-R25-1 (a) planner default;
zero new Cargo dependencies). When run under `valgrind --tool=memcheck`, any
branch / memory-address / store whose value depends on the tainted bytes
triggers a warning pointing to the EXACT source line. The taint propagates
per-byte through every execution path the kernel actually exercises, so a
single execution catches leaks that no finite probed input set could.

### How to run

```sh
./scripts/run-ct-local.sh memcheck
```

5 sub-cases × N=3 = 15 invocations under valgrind. Wall-clock budget:
~2-5 min on x86_64 (memcheck overhead ~30-50× native; the kernels are
sub-millisecond native, so each invocation completes in a few seconds).

### Acceptance gate (LOAD-BEARING per SD-R25-5)

Zero un-suppressed memcheck warnings (any of: "Conditional jump or move
depends on uninitialised value(s)", "Use of uninitialised value of size N",
etc.) across all 15 invocations = PASS (wrapper exit 0). Any un-suppressed
warning = FAIL (wrapper exit 1). The PASS summary line is:

```
PASS: scripts/run-ct-local.sh memcheck (15 invocations, zero taint violations)
```

### Override-path procedure (MEDIUM-4)

If memcheck flags legitimate non-leak code (e.g., allocator metadata
access; panic-formatting paths; documented domain-error guards on a
kernel), the maintainer's escape hatch is to add an entry to the valgrind
suppression file at `valgrind/memcheck-suppressions.txt`. Each entry
requires:

- A justification comment explaining why the flagged code is non-leak.
- The date the entry was added (YYYY-MM-DD).
- A reviewer signature line.

Entries are reviewed at each R-round closure for staleness — entries that
no longer apply (e.g., a libc symbol that was suppressed in glibc 2.36 but
is no longer flagged in glibc 2.38) are removed at review time.

The wrapper invokes valgrind with `--suppressions=$REPO_ROOT/valgrind/memcheck-suppressions.txt`
so all documented suppressions apply. The LOAD-BEARING contract is
preserved: the wrapper continues to exit non-zero on any *un-suppressed*
warning; the suppression file is for documented exceptions only.

The initial post-R25-01 commit ships a suppression entry for the documented
`inv(0) -> Err` domain-error guard at `src/legacy.rs:115`: the
`if a == 0 { return Err(...) }` branch is input-dependent (it tests a byte
we just tainted) but is DELIBERATE + outside the CT contract (the CT
property covers `inv` only over the valid GF(2^8) domain `a in [1, 255]`;
production code never reaches `inv(0)` per R20 + recover-module validation).
The branchless `a^254` square-and-multiply body is independently verified
at the cachegrind 16-class + KernelDisass.html instruction-level axes.

### Cross-references (R25-01)

- The cachegrind 312/312 zero counter-delta gate (LOAD-BEARING per R24 v4
  amendment path (c)) is byte-identical pre/post-R25 — R25 does NOT change
  that gate's pass/fail semantics; the cachegrind subcommand is UNCHANGED.
- The dudect ADVISORY-only contract (`./scripts/run-ct-local.sh dudect`
  exits 0 always) is byte-identical pre/post-R25 — R25 does NOT amend
  dudect's posture (R24 v4 path (c) + R26 HIGH-1 (a) preserved verbatim).
- Memcheck-taint adds ONE NEW LOAD-BEARING surface ORTHOGONAL to cachegrind
  312/312 + KernelDisass.html (3 LOAD-BEARING axes total post-R25).

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

Per FIX_PLAN.html #r22-v2-changelog Amendment 4 + #r24-acceptance v3 +
#r26-03 (R26 post-uplift denominator):

1. **Re-run on the same local host with the same seed**. The deterministic
   seed `DUDECT_RNG_SEED = 0x756e6963_6f72_6e75` makes the run
   reproducible. A `|t| ≥ 10` on a single noisy sample MAY be a runner-side
   tail outlier; the 20× re-run regime (R26-03 uplift from 5×) amortises
   this across 16 sliding-window positions (runs 1-5, 2-6, ..., 16-20).

2. **If 5 consecutive same-sub-case |t| ≥ 10 transients appear in ANY of
   the 16 sliding-window positions** across the 20 runs: this is a REAL
   production-code timing bug per the R22 v2 Amendment 4 absolute 5/5
   threshold (preserved in R26-03 per SD-R26-7 + maintainer-locked HIGH-1
   (a) — NOT relativized to 25%). Surface it as a separate R-FIX round
   to fix the production code BEFORE the next release tag. Do NOT modify
   the harness to suppress the signal. The wrapper does NOT contain a
   programmatic 5-consecutive-runs sliding-window scanner; this step is a
   MANUAL human review of the per-(run, sub-case) transient forensic
   output emitted at the bottom of `run_dudect()`.

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
