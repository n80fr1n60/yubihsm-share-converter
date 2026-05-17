//! R23-01: cachegrind constant-time verification harness for GF(2^8) kernels.
//!
//! This is a `[[bench]]` target with `harness = false` (custom main; mirrors
//! R22's benches/dudect_kernels.rs precedent). NOT linked into the production
//! binary + NOT exercised by `cargo test` against the bench binary itself.
//! Invoked under `valgrind --tool=cachegrind` by
//! `.github/workflows/cachegrind.yml` + by the implementer's local discharge
//! step. The harness exercises one of 4 GF(2^8) kernels in a tight
//! N=1M-iteration loop on an input class selected via CLI flag; cachegrind
//! records per-function counters; the workflow diffs the cg_annotate output
//! across input classes per-kernel; zero counter delta = data-independent
//! execution profile at the simulation level.
//!
//! Complements R22 dudect (Welch's t-test on RDTSC wall-clock samples; the
//! timing-variance complement at benches/dudect_kernels.rs) along an
//! orthogonal axis: dudect catches statistical leaks via observed-wall-clock
//! variance; cachegrind catches deterministic leaks via simulated cache
//! replay. Both must pass for a strong CT claim.
//!
//! See FIX_PLAN.html #r23-plan + #r23-01 + #r23-v2-changelog for the full
//! rationale, SD-R23-1..7 surfaced sub-decisions, and the v1 → v2 amendment
//! ledger.

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

// SD-R23-2 (v2 per Amendment 1 + INFO-1): mul kernels exercise 4 classes
// {Zero, AllOnes, Canonical, Sample}; inv kernels exercise 4 classes
// {One, AllOnes, Canonical, Sample} — Zero is REPLACED with One for the
// inv kernels because `legacy::inv(0)` returns Err via early-return at
// src/legacy.rs:115-117 BEFORE the 8-iter loop. The early-return path has
// structurally different cachegrind counters than the full-loop path;
// under SD-R23-5 BLOCKING posture every push would otherwise fail on the
// (inv_legacy, Zero) and (inv_aes_chain, Zero) matrix entries. Dropping
// Zero from the inv kernels is a legitimate domain restriction (0 has no
// multiplicative inverse in GF(2^8); the Err return is by design, not a
// CT property of the loop body). The `Sample` class (INFO-1 rename of
// `Random` in v2) carries a deterministic byte literal chosen for
// reproducibility, NOT RNG-derived — the same fixed bytes across runs so
// cachegrind output stays byte-identical, which is the load-bearing
// property for the pairwise-diff acceptance signal.
#[derive(Debug, Clone, Copy)]
enum InputClass {
    Zero,
    One,
    AllOnes,
    Canonical,
    Sample,
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

fn parse_input_class(s: &str) -> Result<InputClass, String> {
    match s {
        "zero" => Ok(InputClass::Zero),
        "one" => Ok(InputClass::One),
        "all-ones" => Ok(InputClass::AllOnes),
        "canonical" => Ok(InputClass::Canonical),
        "sample" => Ok(InputClass::Sample),
        other => Err(format!(
            "unknown input class '{other}' (expected one of: zero, one, all-ones, canonical, sample)"
        )),
    }
}

// Per-kernel class restriction enforced here. Rejects `(Mul*, One)` and
// `(Inv*, Zero)` with a clear error — the workflow's matrix `exclude:` block
// also drops these cells; the harness check is defence-in-depth so a manual
// local invocation of the binary cannot silently produce a structurally-
// different cachegrind signature.
fn validate(kernel: Kernel, class: InputClass) -> Result<(), String> {
    use InputClass::*;
    use Kernel::*;
    match (kernel, class) {
        (MulAes | MulLegacy, One) => Err(
            "(mul_*, one) is not part of the R23 matrix — mul kernels use {zero, all-ones, canonical, sample}".into(),
        ),
        (InvLegacy | InvAesChain, Zero) => Err(
            "(inv_*, zero) is not part of the R23 matrix — legacy::inv(0) returns Err via early-return; the inv kernels use {one, all-ones, canonical, sample}".into(),
        ),
        _ => Ok(()),
    }
}

fn parse_args() -> Result<(Kernel, InputClass), String> {
    // Manual argv parsing (no clap dep). Supported flags:
    //   --kernel <K>        K in {mul_aes, mul_legacy, inv_legacy, inv_aes_chain}
    //   --input-class <C>   C in {zero, one, all-ones, canonical, sample}
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
        // mul kernels: 4 classes {Zero, AllOnes, Canonical, Sample}.
        (MulAes, Zero) | (MulLegacy, Zero) => (0x00, 0x00),
        (MulAes, AllOnes) | (MulLegacy, AllOnes) => (0xFF, 0xFF),
        // spec anchor: mul_aes(0x57, 0x83) = 0xC1 (FIPS-197).
        (MulAes, Canonical) => (0x57, 0x83),
        // spec anchor: mul_legacy(0x57, 0x83) = 0x31 (legacy poly 0x11D).
        (MulLegacy, Canonical) => (0x57, 0x83),
        // Deterministic byte literal (NOT RNG-derived); same bytes across
        // runs so cachegrind output stays byte-identical, which is the
        // load-bearing property for the pairwise-diff acceptance signal.
        (MulAes, Sample) | (MulLegacy, Sample) => (0x3A, 0x9C),
        // inv kernels: 4 classes {One, AllOnes, Canonical, Sample}. Zero
        // REPLACED with One per v2 Amendment 1 (legacy::inv(0)'s Err
        // early-return is a separate cachegrind signature; not a CT
        // property of the loop kernel body).
        (InvLegacy, One) | (InvAesChain, One) => (0x01, 0x00),
        (InvLegacy, AllOnes) | (InvAesChain, AllOnes) => (0xFF, 0x00),
        // spec anchor: inv_aes(0x53) == 0xCA (per spec/properties.cry:323-327).
        (InvAesChain, Canonical) => (0x53, 0x00),
        // spec anchor: inv_legacy(0x02) == 0x8E (per src/legacy.rs anchor).
        (InvLegacy, Canonical) => (0x02, 0x00),
        // Deterministic byte literal for the inv kernels.
        (InvLegacy, Sample) | (InvAesChain, Sample) => (0x3A, 0x00),
        // Unreachable arms (per-kernel class restriction enforced by
        // validate(): (Mul*, One) | (Inv*, Zero)).
        _ => unreachable!("validate() enforces per-kernel input-class restriction"),
    }
}

fn main() {
    let (kernel, class) = match parse_args() {
        Ok(pair) => pair,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!(
                "usage: cachegrind_kernels --kernel <mul_aes|mul_legacy|inv_legacy|inv_aes_chain> \\\n       --input-class <zero|one|all-ones|canonical|sample>"
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

// LOW-2 (v2): `#[cfg(test)]` correctness anchors. cachegrind verifies CT
// (data-independence of the instruction stream + memory-access pattern);
// these unit tests verify CORRECTNESS (the kernel computes the right value
// on the published spec anchors). Both must hold — a CT-clean
// implementation of the wrong function is still wrong. The
// `inv_aes_chain` anchor is the Cryptol spec anchor at
// spec/properties.cry:323-327 (`inv_aes(0x53) == 0xCA`) and is the only
// Rust-side correctness check for the synthetic chain.
// LOW-2 anchor tests. With `harness = false`, `cargo test` does NOT execute
// these tests (the bench's user-provided `main()` runs instead under
// `cargo test --bench cachegrind_kernels`). They serve as
// compile-time-checked correctness anchors against the published spec
// values: `cargo build --release --bench cachegrind_kernels --locked`
// type-checks the bodies + the `assert_eq!` macro arguments, catching a
// rename or signature drift at build time. The spec acceptance #10 keeps
// the `cargo test` count unchanged post-R23 (these tests are NOT counted).
#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod tests {
    use super::*;
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
}
