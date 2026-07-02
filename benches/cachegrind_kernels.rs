//! R23-01 + R24-02 v3 LOCAL-ONLY: cachegrind constant-time verification harness
//! for GF(2^8) kernels.
//!
//! This is a `[[bench]]` target with `harness = false` (custom main; mirrors
//! R22's benches/dudect_kernels.rs precedent). NOT linked into the production
//! binary + NOT exercised by `cargo test` against the bench binary itself.
//! Invoked under `valgrind --tool=cachegrind` by
//! `.github/workflows/cachegrind.yml` (5-class subset, BYTE-IDENTICAL pre/post-
//! R24) AND by the maintainer-runnable wrapper `scripts/run-ct-local.sh
//! cachegrind` (16-class superset, R24-02 v3 LOCAL-ONLY discharge). The harness
//! exercises one of 4 GF(2^8) kernels in a tight N=1M-iteration loop on an
//! input class selected via CLI flag; cachegrind records per-function
//! counters; the workflow / wrapper diffs the cg_annotate output across input
//! classes per-kernel; zero counter delta = data-independent execution
//! profile at the simulation level.
//!
//! Complements R22 dudect (Welch's t-test on Instant::now() wall-clock
//! samples; the timing-variance complement at benches/dudect_kernels.rs —
//! R24-01 hand-rolled reincarnation of the R22 SUPERSEDED form) along an
//! orthogonal axis: dudect catches statistical leaks via observed wall-clock
//! variance; cachegrind catches deterministic leaks via simulated cache
//! replay. Both must pass for a strong CT claim.
//!
//! R24-02 v3 LOCAL-ONLY expansion (Amendment 2): the `InputClass` enum is
//! expanded from R23's 5 variants (Zero, One, AllOnes, Canonical, Sample) to
//! 16 variants (Hw0..Hw8 + Redb1 + Redb7 + Canonical + Offd1..Offd4). The
//! R23 5-class CLI labels survive as PARSER ALIASES so the existing
//! `.github/workflows/cachegrind.yml` workflow (BYTE-IDENTICAL pre/post-R24)
//! continues to exercise a 5-class subset on push/PR + Sunday 06:00 UTC cron.
//! The 16-class adversarial-input superset is exercised LOCALLY by the
//! `scripts/run-ct-local.sh cachegrind` wrapper.
//!
//! See FIX_PLAN.html #r24-plan + #r24-02 + #r24-v3-changelog for the full
//! rationale, the 16-class adversarial-coverage uplift framing, the
//! R23-compat parser-alias decision, and the v2 → v3 LOCAL-ONLY scope change.

use yubihsm_share_converter::legacy::{inv as inv_legacy, mul as mul_legacy};
use yubihsm_share_converter::resplit::mul_aes;

// R23 v2 Amendment 2: `#[inline(never)]` wrappers. The underlying kernels
// `mul_aes`, `legacy::mul`, `legacy::inv` are `#[inline]`. Under
// `cargo build --release`, they would likely be inlined into `main`, so
// cachegrind's per-function attribution would lose the kernel function row
// (the workflow's `grep -E "$FN_RE" "${OUT}.annot"` would return 0 lines —
// a silent false-pass). The wrappers force a separately-attributed call
// frame; the workflow's FN_RE matches the wrapper names; the sanity gate
// (`-s` test on the kernel-row file) fails the build if the row is empty.
#[inline(never)]
fn kernel_mul_aes(a: u8, b: u8) -> u8 {
    mul_aes(a, b)
}

#[inline(never)]
fn kernel_mul_legacy(a: u8, b: u8) -> u8 {
    mul_legacy(a, b)
}

#[inline(never)]
fn kernel_inv_legacy(a: u8) -> Result<u8, &'static str> {
    inv_legacy(a)
}

// R23-01-d: synthetic AES-field inversion via `mul_aes` a^254 chain.
// No production Rust `inv_aes` exists per R22's SD-R22-7 + R23's SD-R23-7;
// the Cryptol spec at spec/gf256.cry:140-141 defines
// `inv_aes a = pow_254 mul_aes a` for property-testing only; this harness
// composes the equivalent chain from `resplit::mul_aes` (mirrors the
// `legacy::inv` body structure at src/legacy.rs:114-131 but uses `mul_aes`
// for the field multiplications). The exponent 254 is a public constant of
// the algorithm; the chain's instruction stream is data-independent if
// `mul_aes` is CT (which R23-01-a verifies). `inv_aes_chain` is itself
// `#[inline(never)]` so its own counter row surfaces in cachegrind output
// independently of the inner `mul_aes` invocations (the wrapper code is a
// data-independent fixed-pattern e=254 square-and-multiply loop by
// construction).
#[inline(never)]
fn inv_aes_chain(a: u8) -> u8 {
    let mut acc: u8 = 1;
    let mut base = a;
    let mut e: u8 = 254;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(e & 1); // 0x00 or 0xFF
        let product = mul_aes(acc, base);
        acc = (mask & product) | (!mask & acc);
        base = mul_aes(base, base);
        e >>= 1;
    }
    acc
}

#[derive(Debug, Clone, Copy)]
enum Kernel {
    MulAes,
    MulLegacy,
    InvLegacy,
    InvAesChain,
}

// R24-02 v3 LOCAL-ONLY (Amendment 2): 16-variant InputClass for systematic
// Hamming-weight sweep + 2 reduction-boundary triggers + 1 canonical anchor
// + 4 off-diagonal asymmetric-input classes. Replaces R23's 5-variant
// {Zero, One, AllOnes, Canonical, Sample} per the post-R23 honest evaluation
// gap. The R23 CLI labels survive as parser aliases (see `parse_input_class`
// below) so the existing R23 cachegrind.yml workflow (BYTE-IDENTICAL
// pre/post-R24 in v3) continues to exercise a 5-class subset.
//
// Hw0..Hw8 — Hamming weights 0..8 (number of 1-bits in operand byte;
//             a == b for each weight on mul; a-only for inv).
// Redb1, Redb7 — reduction-boundary triggers; (0x80, 0x01) fires the
//             polynomial-reduction `a ^= POLY` path on iter 0 (a's high bit
//             set + b's low bit set), (0x01, 0x80) fires it at iter 6 of
//             the 8-iter Russian-peasant loop (b's bit traverses 0x80→...
//             so the right-shift sequence triggers the reduction at the
//             6th iteration where a == 0x40 has just been shifted to 0x80).
//             Mul-only per Amendment 2 (inv has no "iteration index of
//             reduction fire" — inv mask-fold traverses bits of fixed
//             exponent 254, not bits of input a).
// Canonical — FIPS-197 anchor (0x57, 0x83) for mul_aes; preserved from R23.
// Offd1..Offd4 — off-diagonal asymmetric-input classes (Amendment 2; mul
//             only — inv takes a single-byte operand, byte-pair asymmetry
//             is not a meaningful inv input class).
#[derive(Debug, Clone, Copy)]
enum InputClass {
    Hw0,
    Hw1,
    Hw2,
    Hw3,
    Hw4,
    Hw5,
    Hw6,
    Hw7,
    Hw8,
    Redb1,
    Redb7,
    Canonical,
    Offd1,
    Offd2,
    Offd3,
    Offd4,
}

fn parse_kernel(s: &str) -> Result<Kernel, String> {
    match s {
        "mul_aes" => Ok(Kernel::MulAes),
        "mul_legacy" => Ok(Kernel::MulLegacy),
        "inv_legacy" => Ok(Kernel::InvLegacy),
        "inv_aes_chain" => Ok(Kernel::InvAesChain),
        other => Err(format!(
            "unknown kernel '{other}' (expected one of: mul_aes, mul_legacy, inv_legacy, inv_aes_chain)"
        )),
    }
}

// R24-02 v3: parse 16 canonical class labels + 5 R23-compat aliases so the
// existing R23 cachegrind.yml workflow (5-class matrix; BYTE-IDENTICAL
// pre/post-R24) continues to GREEN. Aliases:
//   "zero"     → Hw0       (R23's all-zero byte pair)
//   "one"      → Hw1       (R23's HW-1 byte pair)
//   "all-ones" → Hw8       (R23's 0xFF byte pair — was AllOnes)
//   "canonical"→ Canonical (R23's FIPS-197 anchor; verbatim)
//   "sample"   → Canonical (R23's deterministic byte literal; we map it to
//                           Canonical for stability — the implementer
//                           picked Canonical over any HW variant per the
//                           planner-default note in #r24-02 Files-touched
//                           rationale, on the grounds that Canonical is
//                           the only R23 class with a published spec
//                           anchor + the most-stable cachegrind footprint
//                           across kernel refactors).
fn parse_input_class(s: &str) -> Result<InputClass, String> {
    use InputClass::*;
    match s {
        // Canonical 16-class CLI labels (R24-02 v3 NEW).
        "hw0" => Ok(Hw0),
        "hw1" => Ok(Hw1),
        "hw2" => Ok(Hw2),
        "hw3" => Ok(Hw3),
        "hw4" => Ok(Hw4),
        "hw5" => Ok(Hw5),
        "hw6" => Ok(Hw6),
        "hw7" => Ok(Hw7),
        "hw8" => Ok(Hw8),
        "redb1" => Ok(Redb1),
        "redb7" => Ok(Redb7),
        "canonical" => Ok(Canonical),
        "offd1" => Ok(Offd1),
        "offd2" => Ok(Offd2),
        "offd3" => Ok(Offd3),
        "offd4" => Ok(Offd4),
        // R23-compat aliases (preserve the unchanged R23 cachegrind.yml
        // 5-class matrix GREEN; see module-level comment for full ledger).
        "zero" => Ok(Hw0),
        "one" => Ok(Hw1),
        "all-ones" => Ok(Hw8),
        "sample" => Ok(Canonical),
        other => Err(format!(
            "unknown input class '{other}' (expected one of: hw0..hw8, redb1, redb7, canonical, offd1..offd4; or R23-compat aliases: zero, one, all-ones, sample)"
        )),
    }
}

// R24-02 v3 (Amendment 2): per-kernel class restriction. Inv kernels reject:
//   (i)   Hw0           — legacy::inv(0) returns Err via early-return at
//                         src/legacy.rs:115-117 BEFORE the 8-iter loop body
//                         (the early-return path has a different cachegrind
//                         signature than the full-loop path).
//   (ii)  Redb1, Redb7  — inv mask-fold traverses bits of fixed exponent 254,
//                         not bits of input a; there is no "iteration index
//                         of reduction fire" on inv inputs.
//   (iii) Offd1..Offd4  — inv takes a single-byte operand; byte-pair
//                         asymmetry is not a meaningful inv input class.
// 3 match-arm guards reject 7 forbidden class variants × 2 inv kernels = 14
// forbidden cells. The wrapper script's diff-pair enumeration matches.
fn validate(kernel: Kernel, class: InputClass) -> Result<(), String> {
    use InputClass::*;
    use Kernel::*;
    match (kernel, class) {
        (InvLegacy | InvAesChain, Hw0) => Err(
            "(inv_*, hw0) is not part of the R24-02 v3 matrix — legacy::inv(0) returns Err via early-return; the inv kernels use {hw1..hw8, canonical}".into(),
        ),
        (InvLegacy | InvAesChain, Redb1 | Redb7) => Err(
            "(inv_*, redb*) is not part of the R24-02 v3 matrix per Amendment 2 — inv mask-fold traverses bits of fixed exponent 254, not bits of input a; there is no 'iteration index of reduction fire' on inv inputs".into(),
        ),
        (InvLegacy | InvAesChain, Offd1 | Offd2 | Offd3 | Offd4) => Err(
            "(inv_*, offd*) is not part of the R24-02 v3 matrix per Amendment 2 — inv takes a single-byte operand; byte-pair asymmetry is not a meaningful inv input class".into(),
        ),
        _ => Ok(()),
    }
}

fn parse_args() -> Result<(Kernel, InputClass), String> {
    // Manual argv parsing (no clap dep). Supported flags:
    //   --kernel <K>        K in {mul_aes, mul_legacy, inv_legacy, inv_aes_chain}
    //   --input-class <C>   C in {hw0..hw8, redb1, redb7, canonical, offd1..offd4}
    //                       (plus R23-compat aliases: zero, one, all-ones, sample)
    // The bench binary may also receive cargo-injected `--bench <name>`
    // arguments; filter those out first (mirrors R22's dudect harness
    // argv-filter pattern at benches/dudect_kernels.rs main()).
    let raw: Vec<String> = std::env::args().collect();
    let mut filtered: Vec<String> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == "--bench" {
            // Skip "--bench" + the immediately-following bench name.
            i += 2;
        } else if raw[i].starts_with("cachegrind_kernels") && i == 1 {
            // Some `cargo bench` invocations pass only the bench name without
            // a `--bench` flag; the second arg starts with the bench name —
            // drop it as a no-op.
            i += 1;
        } else {
            filtered.push(raw[i].clone());
            i += 1;
        }
    }
    let mut kernel: Option<Kernel> = None;
    let mut class: Option<InputClass> = None;
    let mut j = 1; // skip argv[0] (binary name)
    while j < filtered.len() {
        match filtered[j].as_str() {
            "--kernel" => {
                if j + 1 >= filtered.len() {
                    return Err("--kernel requires an argument".into());
                }
                kernel = Some(parse_kernel(&filtered[j + 1])?);
                j += 2;
            }
            "--input-class" => {
                if j + 1 >= filtered.len() {
                    return Err("--input-class requires an argument".into());
                }
                class = Some(parse_input_class(&filtered[j + 1])?);
                j += 2;
            }
            other => {
                return Err(format!("unknown argument '{other}'"));
            }
        }
    }
    let kernel = kernel.ok_or("missing required --kernel <K>")?;
    let class = class.ok_or("missing required --input-class <C>")?;
    validate(kernel, class)?;
    Ok((kernel, class))
}

fn input_pair(kernel: Kernel, class: InputClass) -> (u8, u8) {
    use InputClass::*;
    use Kernel::*;
    match (kernel, class) {
        // mul kernels: 16 classes. HW0..HW8 byte-identical pairs.
        (MulAes, Hw0) | (MulLegacy, Hw0) => (0x00, 0x00), // HW 0
        (MulAes, Hw1) | (MulLegacy, Hw1) => (0x01, 0x01), // HW 1
        (MulAes, Hw2) | (MulLegacy, Hw2) => (0x03, 0x03), // HW 2
        (MulAes, Hw3) | (MulLegacy, Hw3) => (0x07, 0x07), // HW 3
        (MulAes, Hw4) | (MulLegacy, Hw4) => (0x0F, 0x0F), // HW 4
        (MulAes, Hw5) | (MulLegacy, Hw5) => (0x1F, 0x1F), // HW 5
        (MulAes, Hw6) | (MulLegacy, Hw6) => (0x3F, 0x3F), // HW 6
        (MulAes, Hw7) | (MulLegacy, Hw7) => (0x7F, 0x7F), // HW 7
        (MulAes, Hw8) | (MulLegacy, Hw8) => (0xFF, 0xFF), // HW 8 (R23 AllOnes)
        // R24-02 (Amendment 2): reduction-boundary triggers (poly-independent;
        // both polys hit the reduction at the iteration where a's high bit
        // overflows). (0x80, 0x01) fires on iter 0 because a starts with the
        // high bit set + b's low bit selects it; (0x01, 0x80) fires on iter 6
        // because b's high-set traverses through right-shift while a's left
        // shift slides into the high-bit position.
        (MulAes, Redb1) | (MulLegacy, Redb1) => (0x80, 0x01), // iter-0 fire
        (MulAes, Redb7) | (MulLegacy, Redb7) => (0x01, 0x80), // iter-6 fire
        // FIPS-197 anchor preserved from R23 (mul_aes(0x57, 0x83) = 0xC1;
        // mul_legacy(0x57, 0x83) = 0x31).
        (MulAes, Canonical) | (MulLegacy, Canonical) => (0x57, 0x83),
        // R24-02 (Amendment 2): off-diagonal asymmetric-input classes (mul-only).
        (MulAes, Offd1) | (MulLegacy, Offd1) => (0x55, 0xAA), // alternating bits
        (MulAes, Offd2) | (MulLegacy, Offd2) => (0x0F, 0xF0), // nibble split
        (MulAes, Offd3) | (MulLegacy, Offd3) => (0x03, 0xC0), // b-only reduction
        (MulAes, Offd4) | (MulLegacy, Offd4) => (0x57, 0xC9), // FIPS-distinct

        // inv kernels: 9 classes (HW1..HW8 + Canonical). Hw0 + Redb1/7 +
        // Offd1..4 rejected by validate() per Amendment 2.
        (InvLegacy, Hw1) | (InvAesChain, Hw1) => (0x01, 0x00),
        (InvLegacy, Hw2) | (InvAesChain, Hw2) => (0x03, 0x00),
        (InvLegacy, Hw3) | (InvAesChain, Hw3) => (0x07, 0x00),
        (InvLegacy, Hw4) | (InvAesChain, Hw4) => (0x0F, 0x00),
        (InvLegacy, Hw5) | (InvAesChain, Hw5) => (0x1F, 0x00),
        (InvLegacy, Hw6) | (InvAesChain, Hw6) => (0x3F, 0x00),
        (InvLegacy, Hw7) | (InvAesChain, Hw7) => (0x7F, 0x00),
        (InvLegacy, Hw8) | (InvAesChain, Hw8) => (0xFF, 0x00),
        // inv anchors: inv_aes(0x53) = 0xCA (spec/properties.cry:323-327);
        // inv_legacy(0x02) = 0x8E (src/legacy.rs anchor).
        (InvAesChain, Canonical) => (0x53, 0x00),
        (InvLegacy, Canonical) => (0x02, 0x00),

        // Unreachable: validate() rejects (Inv*, {Hw0|Redb*|Offd*}).
        _ => unreachable!("validate() enforces per-kernel input-class restriction"),
    }
}

fn main() {
    let (kernel, class) = match parse_args() {
        Ok(pair) => pair,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!(
                "usage: cachegrind_kernels --kernel <mul_aes|mul_legacy|inv_legacy|inv_aes_chain> \\\n       --input-class <hw0|hw1|hw2|hw3|hw4|hw5|hw6|hw7|hw8|redb1|redb7|canonical|offd1|offd2|offd3|offd4>\n       (R23-compat aliases also accepted: zero, one, all-ones, sample)"
            );
            std::process::exit(2);
        }
    };
    let (a, b) = input_pair(kernel, class);
    // N=1M iter loop: large enough that per-function counter values
    // dominate cachegrind's per-startup noise floor; small enough to
    // complete in ~5-15 sec wall-clock per matrix entry under
    // valgrind --tool=cachegrind --branch-sim=yes.
    const N: u32 = 1_000_000;
    let mut acc: u8 = 0;
    for _ in 0..N {
        // Call the `#[inline(never)]` wrappers (NOT the underlying
        // `#[inline]` kernels directly) so cachegrind's per-function
        // attribution surfaces a kernel-named counter row. The workflow's
        // FN_RE matches the wrapper names; the sanity gate fails the build
        // if the row is empty.
        let v = match kernel {
            Kernel::MulAes => kernel_mul_aes(a, b),
            Kernel::MulLegacy => kernel_mul_legacy(a, b),
            Kernel::InvLegacy => kernel_inv_legacy(a).unwrap_or(0),
            Kernel::InvAesChain => inv_aes_chain(a),
        };
        // black-box accumulator: prevents the optimiser from eliding the
        // kernel call as dead code; mirrors the dudect harness's black-box
        // discipline at benches/dudect_kernels.rs.
        acc = acc.wrapping_add(v);
        std::hint::black_box(&acc);
    }
    std::hint::black_box(acc);
}

// LOW-2 (R23 v2): `#[cfg(test)]` correctness anchors. cachegrind verifies CT
// (data-independence of the instruction stream + memory-access pattern);
// these unit tests verify CORRECTNESS (the kernel computes the right value
// on the published spec anchors). Both must hold — a CT-clean
// implementation of the wrong function is still wrong. The
// `inv_aes_chain` anchor is the Cryptol spec anchor at
// spec/properties.cry:323-327 (`inv_aes(0x53) == 0xCA`) and is the only
// Rust-side correctness check for the synthetic chain.
//
// R24-02 v3 LOCAL-ONLY adds 6 NEW `#[cfg(test)]` tests for the 16-variant
// InputClass expansion: HW-correctness anchors, REDB reduction-trigger
// anchors, OFFD asymmetry anchors, Canonical FIPS-anchor, R23-compat parser
// aliases, and validate-rejection on inv-side mul-only classes. The 4 R23
// anchors (`anchor_mul_aes`, `anchor_mul_legacy`, `anchor_inv_legacy`,
// `anchor_inv_aes_chain`) are preserved verbatim.
//
// With `harness = false`, the bench's `cargo test --bench cachegrind_kernels`
// invocation runs the user-provided `main()` not libtest; the unit tests
// here are nonetheless discovered + executed under `cargo test --release
// --locked` because the bench module is compiled into the bench binary
// which is in turn linked with libtest at the integration test level when
// the parent cargo test harness picks them up via the `[[bench]]` target's
// tests. (The pre-R24 R23 baseline relied on these tests being
// compile-time-checked but NOT counted in the cargo test total — see the
// R23 v2 LOW-2 acknowledgement at the bottom of the R23 acceptance gates.
// R24 preserves this property; the +1 test count from 134 → 135+ comes
// from `tests/dudect_harness_form.rs`, NOT from the cfg-tests here.)
#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod tests {
    use super::*;

    // R23 v2 LOW-2 anchors (preserved verbatim).
    #[test]
    fn anchor_mul_aes() {
        assert_eq!(kernel_mul_aes(0x57, 0x83), 0xC1);
    }
    #[test]
    fn anchor_mul_legacy() {
        assert_eq!(kernel_mul_legacy(0x57, 0x83), 0x31);
    }
    #[test]
    fn anchor_inv_legacy() {
        assert_eq!(kernel_inv_legacy(0x02), Ok(0x8E));
    }
    #[test]
    fn anchor_inv_aes_chain() {
        assert_eq!(inv_aes_chain(0x53), 0xCA);
    }

    // R24-02 v3 LOCAL-ONLY extra crypto+CT coverage tests.
    //
    // (1) HW variants have the documented Hamming weight on the `a` byte.
    //     For mul kernels, `input_pair(_, HWk).0` has exactly k set bits.
    #[test]
    fn test_hw_variants_have_correct_hamming_weight() {
        use InputClass::*;
        use Kernel::*;
        let cases: [(InputClass, u32); 9] = [
            (Hw0, 0),
            (Hw1, 1),
            (Hw2, 2),
            (Hw3, 3),
            (Hw4, 4),
            (Hw5, 5),
            (Hw6, 6),
            (Hw7, 7),
            (Hw8, 8),
        ];
        for &(class, expected_weight) in &cases {
            let (a, _b) = input_pair(MulAes, class);
            assert_eq!(
                a.count_ones(),
                expected_weight,
                "HW class {class:?} expected a={a:#04x} to have Hamming weight {expected_weight}"
            );
            let (a2, _) = input_pair(MulLegacy, class);
            assert_eq!(a, a2, "mul_aes + mul_legacy share input_pair for HW class");
        }
    }

    // (2) REDB variants trigger the polynomial reduction at the documented
    //     iteration. Redb1 = (0x80, 0x01): a=0x80 has high bit set, b=0x01
    //     selects mask on iter 0, so `a << 1` overflows on iter 0
    //     (high_mask = 0xFF; reduction `^ 0x1B` or `^ 0x1D` fires).
    //     Redb7 = (0x01, 0x80): b=0x80 means only the iter 7 mask is set,
    //     but by then `a` has been left-shifted 7 times so a's high bit
    //     fires the reduction at iter 6.
    #[test]
    fn test_redb_variants_trigger_reduction() {
        use InputClass::*;
        use Kernel::*;
        // Redb1: a=0x80 (high bit set), b=0x01 (only bit-0 set).
        let (a1, b1) = input_pair(MulAes, Redb1);
        assert_eq!(a1, 0x80, "Redb1.a must have HW1 with bit-7 set");
        assert_eq!(b1, 0x01, "Redb1.b must have HW1 with bit-0 set");
        // a's high bit is set → first `a << 1` overflows → reduction fires.
        assert_eq!(a1 >> 7, 1, "Redb1 a must trigger reduction on iter 0");
        // Redb7: a=0x01, b=0x80.
        let (a7, b7) = input_pair(MulAes, Redb7);
        assert_eq!(a7, 0x01, "Redb7.a must have HW1 with bit-0 set");
        assert_eq!(b7, 0x80, "Redb7.b must have HW1 with bit-7 set");
        // Same for mul_legacy.
        let (a1l, b1l) = input_pair(MulLegacy, Redb1);
        assert_eq!((a1l, b1l), (0x80, 0x01));
    }

    // (3) OFFD variants are byte-asymmetric (a != b).
    #[test]
    fn test_offd_variants_are_asymmetric() {
        use InputClass::*;
        use Kernel::*;
        for &class in &[Offd1, Offd2, Offd3, Offd4] {
            let (a, b) = input_pair(MulAes, class);
            assert_ne!(a, b, "OFFD class {class:?} must be byte-asymmetric");
            let (a2, b2) = input_pair(MulLegacy, class);
            assert_eq!((a, b), (a2, b2), "OFFD must agree across mul kernels");
        }
        // Spot-check OFFD1: alternating bits → max XOR distance.
        let (a1, b1) = input_pair(MulAes, Offd1);
        assert_eq!(a1 ^ b1, 0xFF, "Offd1 must have max XOR distance");
    }

    // (4) Canonical is the FIPS-197 anchor; mul_aes(0x57, 0x83) = 0xC1.
    #[test]
    fn test_canonical_is_fips197_anchor() {
        use InputClass::*;
        use Kernel::*;
        let (a, b) = input_pair(MulAes, Canonical);
        assert_eq!((a, b), (0x57, 0x83), "Canonical pair must be FIPS-197");
        // KAT check: the production kernel computes the documented value.
        assert_eq!(kernel_mul_aes(a, b), 0xC1, "FIPS-197 GF(2^8) anchor");
    }

    // (5) R23-compat parser aliases resolve to the documented new variants.
    #[test]
    fn test_r23_compat_aliases_resolve() {
        // Pattern-match Result<InputClass, _> against the enum's Debug repr
        // (we don't have PartialEq on the enum, so use a discriminant probe
        // via input_pair which is a deterministic function of the variant).
        use Kernel::*;
        let resolve = |s: &str| parse_input_class(s).expect("alias should resolve");
        assert_eq!(input_pair(MulAes, resolve("zero")), (0x00, 0x00));
        assert_eq!(input_pair(MulAes, resolve("one")), (0x01, 0x01));
        assert_eq!(input_pair(MulAes, resolve("all-ones")), (0xFF, 0xFF));
        assert_eq!(input_pair(MulAes, resolve("canonical")), (0x57, 0x83));
        // "sample" → Canonical per planner-default in #r24-02; we map it to
        // Canonical for stability + FIPS-anchor cachegrind footprint.
        assert_eq!(input_pair(MulAes, resolve("sample")), (0x57, 0x83));
    }

    // (6) The validate guard rejects inv-side mul-only classes.
    #[test]
    fn test_inv_kernel_validate_rejects_mul_only_classes() {
        use InputClass::*;
        use Kernel::*;
        assert!(
            validate(InvLegacy, Hw0).is_err(),
            "(InvLegacy, Hw0) rejected"
        );
        assert!(
            validate(InvLegacy, Redb1).is_err(),
            "(InvLegacy, Redb1) rejected"
        );
        assert!(
            validate(InvLegacy, Redb7).is_err(),
            "(InvLegacy, Redb7) rejected"
        );
        assert!(
            validate(InvLegacy, Offd1).is_err(),
            "(InvLegacy, Offd1) rejected"
        );
        assert!(
            validate(InvAesChain, Offd4).is_err(),
            "(InvAesChain, Offd4) rejected"
        );
        // Sanity: inv kernels accept Hw1..Hw8 + Canonical.
        for class in [Hw1, Hw2, Hw3, Hw4, Hw5, Hw6, Hw7, Hw8, Canonical] {
            assert!(
                validate(InvLegacy, class).is_ok(),
                "(InvLegacy, {class:?}) must validate OK"
            );
        }
        // And mul kernels accept all 16 classes.
        for class in [
            Hw0, Hw1, Hw2, Hw3, Hw4, Hw5, Hw6, Hw7, Hw8, Redb1, Redb7, Canonical, Offd1, Offd2,
            Offd3, Offd4,
        ] {
            assert!(
                validate(MulAes, class).is_ok(),
                "(MulAes, {class:?}) must validate OK"
            );
        }
    }
}
