//! Per-byte Lagrange recovery for the legacy field. Pulled out of
//! `main.rs` in R13-C / item 3 so both the production binary and the
//! `fuzz/fuzz_targets/recover.rs` libFuzzer harness can call the SAME
//! function — eliminating the R12-v3 `recover_for_fuzz` wrapper that
//! duplicated the math kernel.
//!
//! SCOPE: this function covers ONLY the per-byte
//! `legacy::interp_at_zero` loop. The disjoint-subset cross-check
//! (n >= 2*t branch), over-determined verification (n > t branch),
//! and `Zeroizing<Vec<u8>>` wrap on the destination blob remain
//! at the call-site in `main.rs` — they are POLICY layered on top
//! of the math kernel, not part of the kernel itself.

use crate::legacy;
use crate::parse::LegacyShare;

/// R9-H2: closure-producing-iterator pattern. `used` is captured by
/// reference; `byte_idx` is captured by copy (usize). Fresh iterator
/// on every call() — Phase 1 + Phase 3 in interp_at_zero each invoke
/// it once. No heap allocation; no leak window. The previous
/// implementation materialised a per-byte `Vec<(u8, u8)>` that held
/// raw share Y-bytes and was dropped without scrubbing every loop
/// iteration — the H2 happy-path leak this refactor closes.
///
/// R12-C-04: signature drops the `tabs: &legacy::Tables` arg — the
/// `Tables` struct was deleted from production code. `mul`/`inv`/
/// `interp_at[_zero]` no longer take it.
///
/// R13-C / item 3: moved from `src/main.rs:381-395` to this module.
/// Body byte-identical to the pre-R13 production body; only the
/// home changed. Fuzz harness in `fuzz/fuzz_targets/recover.rs`
/// imports via `use yubihsm_share_converter::recover::recover;`.
pub fn recover(used: &[LegacyShare], payload_len: usize) -> Result<Vec<u8>, String> {
    let mut blob = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let make_pts = || used.iter().map(|s| (s.index, s.payload[byte_idx]));
        blob.push(legacy::interp_at_zero(make_pts)?);
    }
    Ok(blob)
}
