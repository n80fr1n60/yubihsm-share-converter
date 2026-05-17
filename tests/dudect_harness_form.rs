//! R24-01 v3 LOCAL-ONLY: source-form-guard regression test for
//! `benches/dudect_kernels.rs`. Mirrors R12-C-05's source-form-guard
//! discipline at src/main.rs:2210-2310 + R22 v3 Amendment 9 verbatim
//! except for assertion (viii) which is NEW for R24's hand-rolled posture.
//!
//! Reads the dudect harness source via `include_str!` + runs 10+
//! grep-style assertions locking the v4+v2 invariants. THE only CI-side
//! gate for R24 (the wrapper script is maintainer-runnable, not push-gating).
//! Runs under `cargo test --release --locked` via ci.yml's existing test
//! invocation (no new workflow file). +1 test count: 134 → 135 (or more,
//! given the extra crypto+CT coverage tests in the harness + cachegrind
//! `#[cfg(test)]` modules).
//!
//! See FIX_PLAN.html #r24-01 + #r24-v3-changelog for the full Amendment 9
//! discipline + v3 LOCAL-ONLY scope notes.

const HARNESS_SOURCE: &str = include_str!("../benches/dudect_kernels.rs");

#[test]
fn dudect_harness_form_is_locked() {
    let body = HARNESS_SOURCE;

    // ---- COUNT-BASED ASSERTIONS (require >= N occurrences) ------------------

    // (i) `rng.gen::<bool>()` >= 5 — randomised Class::Left/Right selection
    //     per R22 v3 Amendment 5; one per sub-case (5 sub-cases). The +1
    //     in the test module's class-balance test is an extra anchor; the
    //     floor still requires >= 5.
    let n_gen_bool = body.matches("rng.gen::<bool>()").count();
    assert!(
        n_gen_bool >= 5,
        "R24-01 Amendment 5: require >= 5 occurrences of `rng.gen::<bool>()` for randomised class selection per sub-case (1 per sub-case × 5 sub-cases); found {n_gen_bool}. A future refactor that removed randomisation would defeat the LRLR-defence — see FIX_PLAN.html #r24-01 Amendment 5"
    );

    // (ii) `black_box` >= 10 — input AND output wraps per R22 v3 Amendment
    //      6 (>= 2 per sub-case × 5 sub-cases).
    let n_black_box = body.matches("black_box").count();
    assert!(
        n_black_box >= 10,
        "R24-01 Amendment 6: require >= 10 occurrences of `black_box` for input/output wraps (≥2 per sub-case × 5 sub-cases); found {n_black_box}. Without the wraps the compiler may constant-fold the kernel calls — see FIX_PLAN.html #r24-01 Amendment 6"
    );

    // (iii) `StdRng::seed_from_u64(DUDECT_RNG_SEED)` >= 5 — per-sub-case
    //       deterministic seed per R22 v3 Sec INFO-1 (5 sub-cases × 1
    //       seed each = 5 occurrences; or fewer if the seed is hoisted
    //       to a `let mut rng = ...` at run_bench's top — which is what
    //       the implementation does. The floor catches refactors that
    //       inline the seed in a non-deterministic way.)
    let n_seed = body
        .matches("StdRng::seed_from_u64(DUDECT_RNG_SEED)")
        .count();
    assert!(
        n_seed >= 1,
        "R24-01 Sec INFO-1: require >= 1 occurrence of `StdRng::seed_from_u64(DUDECT_RNG_SEED)` for deterministic per-sub-case seeding; found {n_seed}. Without deterministic seeding, Class::Right byte streams differ across runs — see FIX_PLAN.html #r24-01 Sec INFO-1"
    );

    // (iv) `PERCENTILE_CUTS` >= 1 — v2 Amendment 1 marker. The constant
    //      declaration + the iteration over its values.
    let n_percentile_cuts = body.matches("PERCENTILE_CUTS").count();
    assert!(
        n_percentile_cuts >= 1,
        "R24-01 v2 Amendment 1 (LOAD-BEARING): require >= 1 occurrence of `PERCENTILE_CUTS` for paper-§3.2 percentile cropping; found {n_percentile_cuts}. Without cropping, R24-01 inherits R22 v3's empirical-discharge failure on `ct_mul_legacy` — see FIX_PLAN.html #r24-01 Amendment 1"
    );

    // (v) `t.is_finite()` >= 1 — v2 Amendment 8 NaN/inf guard.
    //     Match both `t.is_finite()` and `t_cut.is_finite()` shapes.
    let n_is_finite =
        body.matches("t.is_finite()").count() + body.matches("t_cut.is_finite()").count();
    assert!(
        n_is_finite >= 1,
        "R24-01 v2 Amendment 8: require >= 1 occurrence of `t.is_finite()` or `t_cut.is_finite()` for NaN/inf defence-in-depth; found {n_is_finite}. Without the guard a degenerate sample produces a cryptic NaN/inf panic — see FIX_PLAN.html #r24-01 Amendment 8"
    );

    // ---- PRESENCE ASSERTIONS (must appear at least once) --------------------

    // (vi) `INNER_BATCH` present — R22 v3 Amendment 7 batch amortisation.
    assert!(
        body.contains("INNER_BATCH"),
        "R24-01 Amendment 7: harness must reference `INNER_BATCH` for Instant::now() resolution amortisation; absent. Without batching, the ~20-100ns clock resolution swamps the ~5ns mul_aes runtime — see FIX_PLAN.html #r24-01 Amendment 7"
    );

    // (vii) welch_t_cropped helper present (v2 Amendment 1 marker).
    assert!(
        body.contains("welch_t_cropped") || body.contains("welch_t"),
        "R24-01 v2 Amendment 1: harness must define a `welch_t` and/or `welch_t_cropped` helper for Welch's t-test computation; absent"
    );

    // (viii) `cuts=` literal in the println output line (load-bearing
    //        format marker the wrapper script's awk parser keys on).
    assert!(
        body.contains("cuts="),
        "R24-01 v2 Amendment 1: harness output line must contain `cuts=` field for the wrapper script's MAX-|t|-across-cuts extraction; absent — see FIX_PLAN.html #r24-01 Amendment 1 awk parser spec"
    );

    // ---- FORBID ASSERTIONS (must NOT appear) --------------------------------

    // (ix) `i % 2` forbid — deterministic LRLR class-interleaving pattern
    //      that R22 v3 Amendment 5 explicitly outlawed.
    assert!(
        !body.contains("i % 2"),
        "R24-01 Amendment 5: harness MUST NOT contain `i % 2` deterministic LRLR class-interleaving (it defeats randomisation); found. Refactor to use `rng.gen::<bool>()` — see FIX_PLAN.html #r24-01 Amendment 5"
    );

    // (x) `ctbench_main!` forbid — R22 dudect-bencher 0.4 macro marker
    //     (the SUPERSEDED-crate-only path).
    assert!(
        !body.contains("ctbench_main!"),
        "R24-01 Amendment 4 + R22 SUPERSEDED: harness MUST NOT contain `ctbench_main!` (the dudect-bencher 0.4 macro from the SUPERSEDED crate); found. R24-01 is hand-rolled — see FIX_PLAN.html #r22-01 SUPERSEDED record"
    );

    // (xi) `thread_rng()` forbid — non-deterministic seeding regression.
    assert!(
        !body.contains("thread_rng()"),
        "R24-01 Sec INFO-1: harness MUST NOT contain `thread_rng()` (non-deterministic seeding breaks per-run reproducibility); found. Use `StdRng::seed_from_u64(DUDECT_RNG_SEED)` — see FIX_PLAN.html #r24-01 Sec INFO-1"
    );

    // (xii) `dudect_bencher` forbid — toxic-transitive-dep crate (the WHOLE
    //       POINT of R24-01 vs R22 SUPERSEDED). Defends against a future
    //       refactor that opportunistically reverts to the SUPERSEDED path.
    assert!(
        !body.contains("dudect_bencher"),
        "R24-01 NEW R24-specific assertion: harness MUST NOT reference `dudect_bencher` (the SUPERSEDED dev-dep with clap 2.34 → unsound atty per RUSTSEC-2021-0145); found. R24-01 is hand-rolled stdlib-only — see FIX_PLAN.html #r22-01 SUPERSEDED record + #r24-01"
    );

    // ---- R24 v3 LOCAL-ONLY EXTRA COVERAGE -----------------------------------
    // The wrapper script's empirical discharge is load-bearing; these extra
    // form-guard assertions defend the harness's structural invariants
    // (exactly 5 percentile cuts; all 5 sub-cases present; cuts_field marker
    // for the awk extraction; sample_split_gate marker — wait, that lives in
    // the wrapper, not the harness; here we anchor the harness-side markers).

    // (xiii) exactly 5 percentile cuts (no more, no less). Search the
    //        PERCENTILE_CUTS array literal for the 5 expected values.
    assert!(
        body.contains("[1.0, 0.95, 0.99, 0.999, 0.9999]")
            || body.contains("[1.0,0.95,0.99,0.999,0.9999]"),
        "R24-01 v2 Amendment 1: PERCENTILE_CUTS must be exactly [1.0, 0.95, 0.99, 0.999, 0.9999] per the paper-§3.2 spec; not found"
    );

    // (xiv) all 5 sub-cases listed in #r24-01 are present in the source.
    for sub in &[
        "dudect_mul_aes_zero",
        "dudect_mul_aes_ff",
        "dudect_mul_legacy_zero",
        "dudect_mul_legacy_ff",
        "dudect_inv_legacy_one",
    ] {
        assert!(
            body.contains(sub),
            "R24-01: harness must contain sub-case `{sub}` per FIX_PLAN.html #r24-01; absent"
        );
    }

    // (xv) cuts_field marker — the wrapper script's awk extracts the
    //      `cuts=` line; the harness builds it via a `cuts_field` Vec.
    //      This is a forensic marker for cross-grepping the implementation
    //      layer with the wrapper layer (acceptance gate per #r24-acceptance).
    assert!(
        body.contains("cuts_field"),
        "R24-01: harness must build the cuts= output via a `cuts_field` Vec for forensic cross-reference with the wrapper's awk parser; absent"
    );

    // (xvi) `harness = false` is communicated in the source-level comment
    //       (defence-in-depth against a refactor that removes the directive
    //       from Cargo.toml without updating the harness comment to match).
    //       The directive itself lives in Cargo.toml; here we anchor the
    //       semantic intent in the harness's own docs.
    assert!(
        body.contains("harness") && body.contains("manual `fn main()`")
            || body.contains("argv-filter"),
        "R24-01: harness must document the `harness = false` + manual `fn main()` discipline in source comments per FIX_PLAN.html #r24-01"
    );
}
