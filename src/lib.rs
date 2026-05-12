//! yubihsm-share-converter library: `legacy` + `parse` + `resplit` +
//! `secret` modules exposed for cross-bin and cross-crate reuse.
//!
//! Split out of `main.rs` in R11/C3 so the `gen_fixture` bin can drop
//! its inline duplicate of the legacy field tables and cross-import
//! `yubihsm_share_converter::legacy` directly (the dedupe lands in
//! R11/C3 commit 3; this commit is the structural prerequisite).
//!
//! R12-Phase-D: `parse` was carved out of `src/main.rs` so the
//! `fuzz/` crate (libFuzzer harnesses for parse/recover/resplit) can
//! import `parse_legacy_share` + `LegacyShare` via this lib. The
//! `recover_for_fuzz` seam exposes the math kernel of the production
//! `recover()` function for the recover-target fuzz harness.

pub mod legacy;
pub mod parse;
pub mod resplit;
pub mod secret;

/// R12-Phase-D / item #6: fuzz-only seam exposing the math kernel of
/// `recover()`.
///
/// SCOPE: this wrapper covers ONLY the per-byte `legacy::interp_at_zero`
/// loop. It does NOT cover:
///   * the disjoint-subset cross-check that production `recover()` runs
///     in `main()` (n >= 2*t branch),
///   * the over-determined verification (n > t branch),
///   * the `Zeroizing<Vec<u8>>` wrap on the destination blob.
///
/// Drift between this wrapper and production `recover()` is a
/// CORRECTNESS bug AND a SECURITY-METHODOLOGY bug: fuzz coverage of the
/// math kernel becomes meaningless if production diverges from the
/// kernel under test. The fuzz target is the `recover_for_fuzz` body
/// alone; any future change to the math kernel (currently
/// `legacy::interp_at_zero` per byte) MUST update this seam in lockstep.
///
/// R13 follow-up (SD-R12-v3-1, locked): move the production `recover()`
/// into a lib module so this duplication can be eliminated structurally
/// — at which point this seam shrinks to a thin re-export.
///
/// PARAMETERS:
///   * `used`: a slice of `LegacyShare`s, each with a non-zero `index`
///     and a `payload` of length ≥ `payload_len`.
///   * `payload_len`: the number of byte positions to recover. Caller
///     is responsible for clamping; this seam does no range validation
///     (the fuzz harness in `fuzz/fuzz_targets/recover.rs` clamps to
///     the 36..=60 legitimate range before calling).
pub fn recover_for_fuzz(
    used: &[crate::parse::LegacyShare],
    payload_len: usize,
) -> Result<Vec<u8>, String> {
    let mut blob = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        // Guard: every share must have at least payload_len bytes. The
        // fuzz harness pre-filters, but the seam stays defensive — a
        // panic on a short payload would be visible to libFuzzer as a
        // bug, masking real ones in `legacy::interp_at_zero`.
        for s in used.iter() {
            if s.payload.len() <= byte_idx {
                return Err(format!(
                    "recover_for_fuzz: share payload length {} < byte_idx+1 = {}",
                    s.payload.len(),
                    byte_idx + 1
                ));
            }
        }
        let make_pts = || used.iter().map(|s| (s.index, s.payload[byte_idx]));
        blob.push(crate::legacy::interp_at_zero(make_pts)?);
    }
    Ok(blob)
}
