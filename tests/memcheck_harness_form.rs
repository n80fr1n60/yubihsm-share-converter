//! R25-01 LOCAL-ONLY: source-form-guard regression test for
//! `benches/memcheck_kernels.rs`. Mirrors `tests/dudect_harness_form.rs`
//! pattern (R12-C-05 + R22 v3 Amendment 9 + R24-01 Amendment 9 + R26-02
//! SAMPLES-floor lineage).
//!
//! Reads the memcheck harness source via `include_str!` and runs 14
//! grep-style assertions plus 1 fs-presence assertion plus 1
//! Cargo.toml `[[bench]]`-count assertion, locking the R25-01 invariants per
//! SD-R25-3 / LOW-1 / LOW-2 / MEDIUM-4 / S-R25-SEC-5. THE only CI-side gate
//! for R25-01 (the wrapper script is maintainer-runnable, not push-gating).
//! Runs under `cargo test --release --locked` via ci.yml's existing test
//! invocation (no new workflow file).
//!
//! +1 test count: 135 -> 136.
//!
//! See FIX_PLAN.html #r25-01 for the full SD-R25-3 11-12 grep plus 1
//! fs-presence assertion list and the LOW-1 / LOW-2 / MEDIUM-4 / S-R25-SEC-5
//! expansions.

const HARNESS_SOURCE: &str = include_str!("../benches/memcheck_kernels.rs");

#[test]
fn memcheck_harness_form_is_locked() {
    let body = HARNESS_SOURCE;

    // ---- (i) 5 sub-case functions present ----------------------------------
    // SD-R25-2 planner default: 5 sub-cases mirroring R24-01 + R26.
    let sub_case_names = [
        "memcheck_mul_aes_zero",
        "memcheck_mul_aes_ff",
        "memcheck_mul_legacy_zero",
        "memcheck_mul_legacy_ff",
        "memcheck_inv_legacy_one",
    ];
    let mut n_subcases = 0usize;
    for sub in &sub_case_names {
        if body.contains(sub) {
            n_subcases += 1;
        }
    }
    assert!(
        n_subcases >= 5,
        "R25-01 SD-R25-2: harness must contain all 5 sub-case names; found {n_subcases} of 5. \
         Expected: {sub_case_names:?}. See FIX_PLAN.html #r25-01 SD-R25-2."
    );

    // ---- (ii) `black_box` count >= 5 ---------------------------------------
    // R24-01 Amendment 6 mirror: input + output wraps to defeat compiler
    // constant-folding + DCE. Each sub-case wraps inputs (a, b) + output;
    // the kernel wrappers also wrap inputs + outputs; >= 5 occurrences is
    // the floor.
    let n_black_box = body.matches("black_box").count();
    assert!(
        n_black_box >= 5,
        "R25-01 (R24-01 Amendment 6 mirror): require >= 5 occurrences of `black_box` for \
         input/output wraps; found {n_black_box}. Without the wraps the compiler may \
         constant-fold the kernel calls. See FIX_PLAN.html #r25-01."
    );

    // ---- (iii) N=3 constant present ----------------------------------------
    // MEDIUM-3 BINARY-signal clarification: memcheck-taint flags on a SINGLE
    // execution; N=3 is for fail-loud robustness against transient PRNG-state
    // effects, NOT a SAMPLES sweep.
    assert!(
        body.contains("const N: usize = 3")
            || body.contains("const N: usize = 3;")
            || body.contains("N: usize = 3"),
        "R25-01 MEDIUM-3: harness must declare `const N: usize = 3` for per-sub-case \
         fail-loud robustness (NOT a SAMPLES sweep); not found. See FIX_PLAN.html \
         #r25-01 MEDIUM-3 clarification."
    );

    // ---- (iv) `valgrind_make_mem_undefined` function name present ----------
    // The hand-rolled inline-asm FFI wrapper per SD-R25-1 (a) planner default.
    let n_vg_fn = body.matches("valgrind_make_mem_undefined").count();
    assert!(
        n_vg_fn >= 1,
        "R25-01 SD-R25-1 (a): harness must reference `valgrind_make_mem_undefined` >= 1 time \
         (the hand-rolled inline-asm FFI wrapper for VALGRIND_MAKE_MEM_UNDEFINED); found \
         {n_vg_fn}. See FIX_PLAN.html #r25-01 SD-R25-1 (a)."
    );

    // ---- (v) `core::arch::asm!` inline-asm FFI marker ----------------------
    // SD-R25-1 (a) planner default: hand-rolled inline-asm FFI macro
    // (zero new Cargo deps). Forbids a future refactor that introduces the
    // `crabgrind` crate dep without the S-R25-SEC-4 cargo-audit hard-gate.
    assert!(
        body.contains("core::arch::asm!"),
        "R25-01 SD-R25-1 (a): harness must contain `core::arch::asm!` invocation for the \
         valgrind client-request inline-asm FFI; not found. See FIX_PLAN.html #r25-01 \
         SD-R25-1 (a)."
    );

    // ---- (vi) kernel imports verbatim from the production crate ------------
    assert!(
        body.contains("yubihsm_share_converter::resplit::mul_aes")
            || body.contains("use yubihsm_share_converter::resplit::mul_aes"),
        "R25-01 SD-R25-2: harness must import `yubihsm_share_converter::resplit::mul_aes`; \
         not found."
    );
    assert!(
        body.contains("yubihsm_share_converter::legacy::"),
        "R25-01 SD-R25-2: harness must import from `yubihsm_share_converter::legacy::`; \
         not found."
    );
    // Specifically: `mul as mul_legacy` and `inv as inv_legacy` per the
    // R24-01 dudect harness pattern.
    assert!(
        body.contains("mul as mul_legacy") || body.contains("legacy::mul"),
        "R25-01 SD-R25-2: harness must import `legacy::mul`; not found."
    );
    assert!(
        body.contains("inv as inv_legacy") || body.contains("legacy::inv"),
        "R25-01 SD-R25-2: harness must import `legacy::inv`; not found."
    );

    // ---- (vii) Manual `fn main()` argv-filter ------------------------------
    // R24-01 Amendment 4 mirror: cargo bench injects `--bench <name>` args
    // that must be filtered.
    assert!(
        body.contains("fn main()"),
        "R25-01 (R24-01 Amendment 4 mirror): harness must declare manual `fn main()` \
         (harness = false); not found."
    );
    assert!(
        body.contains("--kernel"),
        "R25-01 (R24-01 Amendment 4 mirror): harness must accept `--kernel <K>` argv \
         parameter for per-sub-case dispatch by the wrapper; not found."
    );
    assert!(
        body.contains("--bench"),
        "R25-01 (R24-01 Amendment 4 mirror): harness must filter cargo-injected `--bench` \
         args; not found."
    );

    // ---- (viii) No `dudect_bencher` dep ------------------------------------
    // R22 SUPERSEDED record: dudect-bencher 0.6/0.7 → clap 2.34 → unsound
    // atty per RUSTSEC-2021-0145. R25-01 mirrors R24-01's no-toxic-crate
    // discipline: forbid the SUPERSEDED crate name.
    assert!(
        !body.contains("dudect_bencher"),
        "R25-01 (R24-01 mirror): harness MUST NOT reference `dudect_bencher` (R22 \
         SUPERSEDED crate with toxic transitive deps per RUSTSEC-2021-0145); found. See \
         FIX_PLAN.html #r22-01 SUPERSEDED record."
    );

    // ---- (ix) No `i % 2` deterministic LRLR class interleaving -------------
    // R22 v3 Amendment 5: deterministic LRLR class-interleaving is banned
    // because it defeats branch-predictor randomisation (BPU learns the
    // pattern). For memcheck the pattern doesn't matter for the taint
    // signal, but the form-guard discipline is preserved across rounds.
    assert!(
        !body.contains("i % 2"),
        "R25-01 (R22 v3 Amendment 5 mirror): harness MUST NOT contain `i % 2` \
         deterministic LRLR class-interleaving; found. See FIX_PLAN.html #r22-01 \
         Amendment 5."
    );

    // ---- (x) Output line format `kernel=` marker --------------------------
    // The wrapper script greps for `kernel=` lines to confirm each sub-case
    // ran. The form-guard locks this marker in source.
    assert!(
        body.contains("kernel="),
        "R25-01: harness output must include `kernel=` marker for wrapper-side per-sub- \
         case PASS confirmation; not found."
    );

    // ---- (xi) LOW-1: #[cfg(target_arch = \"x86_64\")] gating ---------------
    // SD-R25-7 + LOW-1: inline-asm payload is x86_64-gated. Defends against
    // a refactor that drops the cfg attribute and breaks the build on
    // aarch64 / non-x86_64 hosts.
    assert!(
        body.contains("#[cfg(target_arch = \"x86_64\")]"),
        "R25-01 LOW-1 + SD-R25-7: inline-asm payload must be \
         #[cfg(target_arch = \"x86_64\")]-gated (aarch64 tracked-for-R27+); not found. \
         See FIX_PLAN.html #r25-01 LOW-1 + SD-R25-7."
    );

    // ---- (xii) S-R25-SEC-5: `xchg(q) %rbx, %rbx` magic-instruction marker -
    // The canonical valgrind magic-instruction sentinel. Without it,
    // valgrind silently ignores the macro and bytes are NEVER tainted
    // (= silent false PASS).
    assert!(
        body.contains("xchgq %rbx, %rbx") || body.contains("xchg %rbx, %rbx"),
        "R25-01 S-R25-SEC-5: harness must contain the canonical valgrind magic- \
         instruction marker `xchg(q) %rbx, %rbx`; not found. Without this marker, \
         valgrind silently ignores the client-request macro (= silent false PASS). \
         See FIX_PLAN.html #r25-01 S-R25-SEC-5."
    );

    // ---- (xiii) MEDIUM-4: valgrind/memcheck-suppressions.txt presence ----
    // The override-path file for documented legitimate-stdlib suppressions.
    // Initially empty/minimal; the form-guard locks the file's presence so
    // the wrapper's `--suppressions=` flag always has a target.
    assert!(
        std::path::Path::new("valgrind/memcheck-suppressions.txt").exists(),
        "R25-01 MEDIUM-4: file `valgrind/memcheck-suppressions.txt` must exist \
         (override-path procedure target for the wrapper's --suppressions= flag). \
         See FIX_PLAN.html #r25-01 MEDIUM-4 override-path procedure."
    );

    // ---- (xiv) LOW-2: post-R25 [[bench]] count in Cargo.toml is 3 ---------
    // Was 2 = cachegrind_kernels + dudect_kernels; R25 adds memcheck_kernels.
    let cargo_toml = include_str!("../Cargo.toml");
    let bench_count = cargo_toml.matches("\n[[bench]]").count()
        + (if cargo_toml.starts_with("[[bench]]") {
            1
        } else {
            0
        });
    assert_eq!(
        bench_count, 3,
        "R25-01 LOW-2: expected exactly 3 [[bench]] entries in Cargo.toml \
         (cachegrind_kernels + dudect_kernels + memcheck_kernels); got {bench_count}. \
         See FIX_PLAN.html #r25-01 LOW-2."
    );
}
