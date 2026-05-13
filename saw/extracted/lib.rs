// saw/extracted/lib.rs — committed Rust adapter crate for SAW symbolic
// execution (R13-B / item 2 / R13-v2 M6).
//
// Crate-type is cdylib so rustc emits a linkable LLVM bitcode file
// with all `#[no_mangle]` symbols as discrete callable functions. The
// crate depends on `yubihsm-share-converter` as a path dependency
// (see `saw/extracted/Cargo.toml`) so the production kernel bodies
// are pulled in transitively — the SAW seam is purely additive; no
// behavioural fork from the production code.
//
// Build invocation (R13-v2 M5 — deterministic literal output path):
//   cargo +1.85 rustc --locked \
//       --manifest-path saw/extracted/Cargo.toml \
//       --target-dir saw/extracted/proof-target \
//       --crate-type cdylib --release -- \
//       --emit=llvm-bc \
//       -C codegen-units=1 \
//       -C opt-level=0 \
//       -C lto=off
//
// The SAW script `saw/yubihsm-share-converter.saw` loads the
// resulting bitcode via:
//   m <- llvm_load_module "extracted/proof-target/release/deps/yubihsm_share_converter_saw_extracted.bc";
// and references the `saw_*` symbol names below directly.
//
// `#![no_std]` posture: an earlier review note listed `#![no_std]` as an
// optimisation for SAW LLVM-IR walks. The implementation deliberately
// keeps libstd. Rationale: a no_std cdylib
// requires a hand-rolled `#[panic_handler]` and supporting language
// items, which is non-trivial boilerplate AND opens a per-edition
// drift surface every quarterly toolchain rotation. SAW's LLVM-IR
// walk handles the libstd-linked bitcode for our small `saw_*`
// wrapper bodies without measurable overhead (the wrappers are
// `#[inline(never)]` thin shims; the libstd payload that ends up in
// the bitcode is negligible — the production kernels do not call
// any allocation or I/O primitive). Recorded in `saw/MAINTENANCE.md`
// + cross-referenced from the R13-02 commit message.

// ─── GF arithmetic kernels (R13-v2 M6: stable no-mangle names) ─────────

#[no_mangle]
#[inline(never)]
pub extern "C" fn saw_legacy_mul(a: u8, b: u8) -> u8 {
    yubihsm_share_converter::legacy::mul(a, b)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn saw_resplit_mul_aes(a: u8, b: u8) -> u8 {
    yubihsm_share_converter::resplit::mul_aes(a, b)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn saw_legacy_inv(a: u8) -> u8 {
    // Precondition `a != 0` is enforced by the SAW `llvm_precond
    // {{ a != 0 }}` at the proof site; under that precondition the
    // production function is total, so the `.expect(...)` here is
    // unreachable in any verified execution. (SAW does not
    // symbolically explore the panic edge under a precondition that
    // excludes it.)
    yubihsm_share_converter::legacy::inv(a)
        .expect("saw_legacy_inv: SAW precondition guarantees a != 0")
}

// ─── Monomorphised Lagrange kernels (R13-v2 M6: concrete signatures) ──
//
// The production `legacy::interp_at_zero` accepts a closure-iterator;
// these wrappers monomorphise the closure away by constructing a
// concrete `[(u8, u8); N]` literal and passing `.iter().copied()` to
// the production function. The wrappers are used by
// `saw/lagrange-offline.saw`; the CI-safe SAW driver intentionally
// limits itself to the three GF wrappers above.
//
// The `.expect(...)` panic edge is unreachable under the SAW-side
// preconditions (`x_i != 0` + `x_i != x_j`); SAW does not explore
// the panic branch under a precondition that excludes it. The
// offline/deep proof path may require a patched SAW/Crucible stack or
// longer solver runtime.

#[no_mangle]
#[inline(never)]
pub extern "C" fn saw_interp_at_zero_t2(x1: u8, x2: u8, y1: u8, y2: u8) -> u8 {
    let pts = [(x1, y1), (x2, y2)];
    yubihsm_share_converter::legacy::interp_at_zero(|| pts.iter().copied())
        .expect("saw_interp_at_zero_t2: SAW precondition guarantees xs distinct + nonzero")
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn saw_interp_at_zero_t3(
    x1: u8, x2: u8, x3: u8,
    y1: u8, y2: u8, y3: u8,
) -> u8 {
    let pts = [(x1, y1), (x2, y2), (x3, y3)];
    yubihsm_share_converter::legacy::interp_at_zero(|| pts.iter().copied())
        .expect("saw_interp_at_zero_t3: SAW precondition guarantees xs distinct + nonzero")
}
