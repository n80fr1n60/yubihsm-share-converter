//! R25-01 LOCAL-ONLY: TIMECOP-style memcheck-taint constant-time verification
//! harness for GF(2^8) kernels.
//!
//! Marks secret bytes as "undefined" via the VALGRIND_MAKE_MEM_UNDEFINED
//! client request (hand-rolled inline-asm FFI macro per SD-R25-1 (a) planner
//! default; zero new Cargo dependencies mirroring R24 v3 + R26 invariant).
//! When run under `valgrind --tool=memcheck`, any branch / memory-address /
//! store whose value depends on those tainted bytes triggers a memcheck
//! warning pointing to the EXACT source line. Same dynamic-taint technique
//! BoringSSL + libsodium use (codified as TIMECOP in SUPERCOP).
//!
//! Five sub-cases mirroring R24-01 + R26 per SD-R25-2:
//!   memcheck_mul_aes_zero       Class::Left = (0, 0)
//!   memcheck_mul_aes_ff         Class::Left = (0xFF, 0xFF)
//!   memcheck_mul_legacy_zero    Class::Left = (0, 0)
//!   memcheck_mul_legacy_ff      Class::Left = (0xFF, 0xFF)
//!   memcheck_inv_legacy_one     Class::Left = 1
//!
//! BINARY signal note (MEDIUM-3 clarification): unlike dudect (statistical),
//! memcheck-taint flags on a SINGLE execution; N=3 per sub-case is for
//! fail-loud robustness against transient PRNG-state effects, NOT a SAMPLES
//! sweep. Total: 5 sub-cases x N=3 = 15 invocations under valgrind.
//!
//! Form discipline (locked by tests/memcheck_harness_form.rs):
//!   - `core::arch::asm!` invocation for the canonical x86_64 valgrind
//!     client-request magic NOP sequence (rolq+rolq+rolq+rolq+xchgq) per
//!     S-R25-SEC-5; the `xchgq %rbx, %rbx` marker is the canonical valgrind
//!     magic-instruction sentinel — without it, valgrind silently ignores the
//!     macro and bytes are NEVER tainted (= silent false PASS).
//!   - `#[cfg(target_arch = "x86_64")]` arch-cfg-gating per SD-R25-7 + LOW-1
//!     (aarch64 tracked-for-R27+).
//!   - `core::hint::black_box` wraps on inputs AND outputs (mirror R24-01
//!     Amendment 6 — defeats compiler constant-folding + DCE).
//!   - `#[inline(never)]` on the kernel wrappers (memcheck per-function
//!     attribution).
//!   - `harness = false` (manual `fn main()` with argv-filter mirror of R24-01
//!     Amendment 4 — cargo bench injects `--bench <name>` args that must be
//!     filtered).
//!   - No toxic-transitive-dep dudect crate (forbid; the R22 SUPERSEDED
//!     crate had clap 2.34 -> unsound atty per RUSTSEC-2021-0145).
//!   - No deterministic LRLR class interleaving via modulo-2 indexing
//!     (forbid; R22 v3 Amendment 5 banned the modulo-2 pattern in R24-01).
//!   - No `MaybeUninit` shortcuts (would taint via Rust-side, not valgrind-
//!     side).
//!
//! See FIX_PLAN.html #r25-plan + #r25-01 for full rationale, the SD-R25-1..7
//! sub-decision matrix, and the canonical valgrind client-request opcode
//! sequence reference.
//!
//! `harness = false` + manual `fn main()` + argv-filter discipline mirrors
//! the R24-01 dudect harness pattern.

use core::hint::black_box;
use yubihsm_share_converter::legacy::{inv as inv_legacy, mul as mul_legacy};
use yubihsm_share_converter::resplit::mul_aes;

/// N=3 per sub-case for fail-loud robustness against transient PRNG-state
/// effects. Per MEDIUM-3 clarification: memcheck detects on a SINGLE
/// execution; N=3 is NOT a statistical SAMPLES sweep.
const N: usize = 3;

// ============================================================================
// Hand-rolled inline-asm FFI macro for the valgrind VALGRIND_MAKE_MEM_UNDEFINED
// client request (SD-R25-1 (a) planner default; zero new Cargo dependencies).
// ============================================================================
//
// Translated verbatim from /usr/include/valgrind/valgrind.h v3.18+ which
// defines the canonical x86_64 valgrind client-request magic NOP sequence:
//
//     #define __SPECIAL_INSTRUCTION_PREAMBLE                         \
//         "rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"                    \
//         "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
//
//     __asm__ volatile(__SPECIAL_INSTRUCTION_PREAMBLE
//                      /* %RDX = client_request ( %RAX ) */
//                      "xchgq %%rbx,%%rbx"
//                      : "=d" (_zzq_result)
//                      : "a" (&_zzq_args[0]), "0" (_zzq_default)
//                      : "cc", "memory" );
//
// Valgrind's instrumentation pattern-matches the four `rolq` (rotate-left)
// instructions on %rdi (which are semantic NOPs because 3+13+61+51 = 128 ≡ 0
// mod 64) followed by `xchgq %rbx, %rbx` (also a semantic NOP). The %rbx-%rbx
// xchg is the canonical "magic instruction" sentinel that signals valgrind to
// read the client request descriptor at %rax and place the result in %rdx.
// Without that exact byte pattern, valgrind silently ignores the macro and
// the bytes are NEVER tainted (= silent false PASS on memcheck warnings).
//
// Per S-R25-SEC-5: the form-guard test asserts `xchgq %rbx, %rbx` is present
// in the source — defends against a refactor that drops the marker.
//
// VG_USERREQ__MAKE_MEM_UNDEFINED enum value derivation from
// /usr/include/valgrind/memcheck.h + /usr/include/valgrind/valgrind.h:
//
//   #define VG_USERREQ_TOOL_BASE(a,b) \
//     ((unsigned int)(((a)&0xff) << 24 | ((b)&0xff) << 16))
//
//   VG_USERREQ__MAKE_MEM_NOACCESS  = VG_USERREQ_TOOL_BASE('M','C')     -> 0x4D43_0000
//   VG_USERREQ__MAKE_MEM_UNDEFINED                                     -> 0x4D43_0001
//   VG_USERREQ__MAKE_MEM_DEFINED                                       -> 0x4D43_0002
//
// (`M' = 0x4D, `C' = 0x43; the enum starts at the base value and increments by 1.)

#[cfg(target_arch = "x86_64")]
const VG_USERREQ_MAKE_MEM_UNDEFINED: u64 = 0x4D43_0001;

/// Mark `len` bytes at `ptr` as undefined for memcheck taint propagation.
///
/// SAFETY: caller must ensure `ptr` references at least `len` valid bytes of
/// addressable memory. On non-x86_64 hosts this is a no-op (per SD-R25-7
/// planner default x86_64-only scope; aarch64 tracked-for-R27+).
///
/// The `xchgq %rbx, %rbx` instruction is the canonical valgrind magic-
/// instruction marker per S-R25-SEC-5 — the form-guard regression test at
/// `tests/memcheck_harness_form.rs` asserts its presence in the source.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn valgrind_make_mem_undefined(ptr: *const u8, len: usize) {
    // Build the request descriptor: 6 u64 words.
    // [0] = request code (VG_USERREQ__MAKE_MEM_UNDEFINED)
    // [1] = arg1 (address)
    // [2] = arg2 (length in bytes)
    // [3..5] = unused (0)
    let request: [u64; 6] = [
        VG_USERREQ_MAKE_MEM_UNDEFINED,
        ptr as u64,
        len as u64,
        0,
        0,
        0,
    ];
    let _default: u64 = 0;
    let _result: u64;
    // SAFETY: the asm block matches the canonical valgrind v3.18+
    // VALGRIND_DO_CLIENT_REQUEST_EXPR sequence for x86_64; rolq on %rdi is
    // semantic-NOP (3+13+61+51 = 128 ≡ 0 mod 64); xchgq %rbx,%rbx is a
    // semantic-NOP; both pattern-match valgrind's instrumentation.
    //
    // Constraints:
    //   "=d" (_result)        — output: %rdx = client_request result
    //   "a" (&request[0])     — input: %rax = pointer to request descriptor
    //   "0" (_default)        — input: %rax tied to default (return-value
    //                           when running on the host CPU, not valgrind)
    //
    // clobbers: "cc", "memory" (mirror the C macro's clobber list).
    core::arch::asm!(
        "rolq $3, %rdi",
        "rolq $13, %rdi",
        "rolq $61, %rdi",
        "rolq $51, %rdi",
        "xchgq %rbx, %rbx",
        in("rax") &request[0],
        inout("rdx") _default => _result,
        // %rdi is implicit in the rolq instructions but is not actually
        // read or written semantically; we mark it as clobbered to be safe.
        out("rdi") _,
        options(att_syntax, nostack, preserves_flags),
    );
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(never)]
unsafe fn valgrind_make_mem_undefined(_ptr: *const u8, _len: usize) {
    // No-op fallback for non-x86_64 hosts (SD-R25-7 planner default x86_64-
    // only; aarch64 tracked-for-R27+). On a non-x86_64 host the harness
    // compiles cleanly but the taint-marking macros are no-ops, so memcheck
    // will not surface any leak signal — explicit by design.
}

// ============================================================================
// Kernel wrappers — #[inline(never)] for memcheck per-function attribution.
// ============================================================================

#[inline(never)]
fn kernel_mul_aes(a: u8, b: u8) -> u8 {
    black_box(mul_aes(black_box(a), black_box(b)))
}

#[inline(never)]
fn kernel_mul_legacy(a: u8, b: u8) -> u8 {
    black_box(mul_legacy(black_box(a), black_box(b)))
}

#[inline(never)]
fn kernel_inv_legacy(a: u8) -> u8 {
    black_box(inv_legacy(black_box(a)).unwrap_or(0))
}

// ============================================================================
// Sub-case drivers — one per (kernel, Class::Left) pair.
//
// Each sub-case:
//   (1) allocates a fixed input pair / single byte
//   (2) marks the input bytes as undefined via valgrind_make_mem_undefined()
//   (3) invokes the kernel via the #[inline(never)] wrapper
//   (4) observes the output via black_box
//   (5) prints `kernel=<name> iter=<n> status=OK` for the wrapper to grep
//
// Per MEDIUM-3 BINARY-signal clarification: each sub-case is invoked N=3
// times for fail-loud robustness; the binary signal is the presence/absence
// of a memcheck "Conditional jump or move depends on uninitialised value(s)"
// warning (parsed by valgrind's --error-exitcode=1 flag, not by the harness).
// ============================================================================

fn memcheck_mul_aes_zero() {
    for iter in 0..N {
        let mut a: u8 = 0;
        let mut b: u8 = 0;
        // SAFETY: a, b are stack-local u8s; the addresses are valid for the
        // duration of the inline-asm call. The taint-marking has no effect
        // outside valgrind's instrumentation.
        unsafe {
            valgrind_make_mem_undefined(&a as *const u8, core::mem::size_of::<u8>());
            valgrind_make_mem_undefined(&b as *const u8, core::mem::size_of::<u8>());
        }
        let (a_in, b_in) = black_box((a, b));
        let _ = black_box(kernel_mul_aes(a_in, b_in));
        // Mark a, b defined again before sub-case exit (so the println below
        // doesn't trip on the now-tainted stack slots when Rust formats them).
        a = black_box(0);
        b = black_box(0);
        let _ = (a, b);
        println!("kernel=memcheck_mul_aes_zero iter={iter} status=OK");
    }
}

fn memcheck_mul_aes_ff() {
    for iter in 0..N {
        let mut a: u8 = 0xFF;
        let mut b: u8 = 0xFF;
        unsafe {
            valgrind_make_mem_undefined(&a as *const u8, core::mem::size_of::<u8>());
            valgrind_make_mem_undefined(&b as *const u8, core::mem::size_of::<u8>());
        }
        let (a_in, b_in) = black_box((a, b));
        let _ = black_box(kernel_mul_aes(a_in, b_in));
        a = black_box(0xFF);
        b = black_box(0xFF);
        let _ = (a, b);
        println!("kernel=memcheck_mul_aes_ff iter={iter} status=OK");
    }
}

fn memcheck_mul_legacy_zero() {
    for iter in 0..N {
        let mut a: u8 = 0;
        let mut b: u8 = 0;
        unsafe {
            valgrind_make_mem_undefined(&a as *const u8, core::mem::size_of::<u8>());
            valgrind_make_mem_undefined(&b as *const u8, core::mem::size_of::<u8>());
        }
        let (a_in, b_in) = black_box((a, b));
        let _ = black_box(kernel_mul_legacy(a_in, b_in));
        a = black_box(0);
        b = black_box(0);
        let _ = (a, b);
        println!("kernel=memcheck_mul_legacy_zero iter={iter} status=OK");
    }
}

fn memcheck_mul_legacy_ff() {
    for iter in 0..N {
        let mut a: u8 = 0xFF;
        let mut b: u8 = 0xFF;
        unsafe {
            valgrind_make_mem_undefined(&a as *const u8, core::mem::size_of::<u8>());
            valgrind_make_mem_undefined(&b as *const u8, core::mem::size_of::<u8>());
        }
        let (a_in, b_in) = black_box((a, b));
        let _ = black_box(kernel_mul_legacy(a_in, b_in));
        a = black_box(0xFF);
        b = black_box(0xFF);
        let _ = (a, b);
        println!("kernel=memcheck_mul_legacy_ff iter={iter} status=OK");
    }
}

fn memcheck_inv_legacy_one() {
    for iter in 0..N {
        let mut a: u8 = 1;
        unsafe {
            valgrind_make_mem_undefined(&a as *const u8, core::mem::size_of::<u8>());
        }
        let a_in = black_box(a);
        let _ = black_box(kernel_inv_legacy(a_in));
        a = black_box(1);
        let _ = a;
        println!("kernel=memcheck_inv_legacy_one iter={iter} status=OK");
    }
}

// ============================================================================
// Manual fn main() with argv-filter for the cargo-injected `--bench <name>`
// args + the `--kernel <K>` selector (mirror R24-01 Amendment 4 / dudect
// harness pattern). The wrapper script invokes each sub-case individually so
// the per-sub-case PASS/FAIL is forensic-attributable.
// ============================================================================

fn main() {
    // Filter cargo's --bench <name> injection + the bench-name positional.
    let raw: Vec<String> = std::env::args().collect();
    let mut filtered: Vec<String> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == "--bench" {
            i += 2; // skip --bench + bench name
        } else if raw[i].starts_with("memcheck_kernels") && i == 1 {
            i += 1; // some cargo invocations pass the bench name positionally
        } else {
            filtered.push(raw[i].clone());
            i += 1;
        }
    }

    let mut selected: Option<String> = None;
    let mut j = 1;
    while j < filtered.len() {
        match filtered[j].as_str() {
            "--kernel" => {
                if j + 1 >= filtered.len() {
                    eprintln!("error: --kernel requires an argument");
                    eprintln!(
                        "usage: memcheck_kernels [--kernel <memcheck_mul_aes_zero|memcheck_mul_aes_ff|memcheck_mul_legacy_zero|memcheck_mul_legacy_ff|memcheck_inv_legacy_one>]"
                    );
                    std::process::exit(2);
                }
                selected = Some(filtered[j + 1].clone());
                j += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: memcheck_kernels [--kernel <memcheck_mul_aes_zero|memcheck_mul_aes_ff|memcheck_mul_legacy_zero|memcheck_mul_legacy_ff|memcheck_inv_legacy_one>]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument '{other}'");
                std::process::exit(2);
            }
        }
    }

    #[allow(clippy::type_complexity)]
    let cases: &[(&str, &dyn Fn())] = &[
        ("memcheck_mul_aes_zero", &memcheck_mul_aes_zero),
        ("memcheck_mul_aes_ff", &memcheck_mul_aes_ff),
        ("memcheck_mul_legacy_zero", &memcheck_mul_legacy_zero),
        ("memcheck_mul_legacy_ff", &memcheck_mul_legacy_ff),
        ("memcheck_inv_legacy_one", &memcheck_inv_legacy_one),
    ];

    let mut ran = 0usize;
    for (name, run) in cases {
        if let Some(s) = &selected {
            if s != *name {
                continue;
            }
        }
        run();
        ran += 1;
    }
    if ran == 0 {
        eprintln!("error: --kernel {selected:?} matched no sub-case");
        std::process::exit(2);
    }
}

// ----------------------------------------------------------------------------
// Tests — verify the harness invokes the production kernels with the correct
// expected values (the same KAT anchors R24-01 + R26 use). These run under
// `cargo test --release --locked` because `harness = false` only suppresses
// the libtest main() in the bench binary; cargo test still discovers
// `#[cfg(test)]` modules within the bench target.
// ----------------------------------------------------------------------------

#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_kat_anchors() {
        // FIPS-197 AES GF(2^8) multiplication anchor: 0x57 × 0x83 = 0xC1.
        assert_eq!(kernel_mul_aes(0x57, 0x83), 0xC1, "FIPS-197 mul_aes anchor");
        // Legacy poly 0x11D anchor: mul_legacy(0x57, 0x83) = 0x31.
        assert_eq!(
            kernel_mul_legacy(0x57, 0x83),
            0x31,
            "legacy poly 0x11D mul anchor"
        );
        // inv(1) = 1 (the multiplicative identity is its own inverse).
        assert_eq!(kernel_inv_legacy(1), 1, "inv_legacy(1) = 1");
        // Spec-anchor: inv_legacy(0x02) = 0x8E.
        assert_eq!(
            kernel_inv_legacy(0x02),
            0x8E,
            "legacy::inv anchor 0x02 → 0x8E"
        );
    }
}
