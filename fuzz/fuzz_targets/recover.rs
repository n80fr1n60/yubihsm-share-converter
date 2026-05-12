//! R12-Phase-D / item #6: recover-target libFuzzer harness.
//!
//! INVARIANT: `recover_for_fuzz` MUST never panic on any input
//! `(used, payload_len)` where every share's `payload.len() >=
//! payload_len`. This harness pre-filters parser-rejected lines so the
//! fuzz input becomes a candidate share set, then asserts the math
//! kernel (`legacy::interp_at_zero` per byte) returns without panicking.
//!
//! Coverage target: the per-byte `legacy::interp_at_zero` loop body
//! reached from `src/lib.rs::recover_for_fuzz`. Drift between this
//! seam and production `recover()` would silently invalidate the
//! coverage — see the doc-comment on `recover_for_fuzz` (lib.rs) for
//! the lockstep contract and the R13 follow-up (SD-R12-v3-1) that
//! eliminates the duplication structurally.

#![no_main]
use libfuzzer_sys::fuzz_target;
use yubihsm_share_converter::parse::{parse_legacy_share, LegacyShare};
use yubihsm_share_converter::recover_for_fuzz;

fuzz_target!(|data: &[u8]| {
    // Split fuzz input by newlines; each line is a candidate share.
    // Feed each through the parser; only collect parser-accepted shares.
    let mut shares: Vec<LegacyShare> = Vec::new();
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(line);
        if let Ok(share) = parse_legacy_share(&s) {
            shares.push(share);
        }
    }
    if shares.is_empty() || shares.len() > 32 {
        return;
    }
    // Pick payload_len from the first share's payload length. Clamp to
    // the legitimate AES-wrap-blob range so the harness exercises the
    // production-shape inputs (36..=60). Anything outside that range
    // would be rejected by `validate_payload_len` BEFORE recover() runs
    // in production, so fuzzing it here would only chase a path that
    // production never reaches.
    let payload_len = shares[0].payload.len();
    if !(36..=60).contains(&payload_len) {
        return;
    }
    // All shares must have at least `payload_len` bytes — otherwise
    // recover_for_fuzz's defensive guard rejects (which is correct
    // behaviour, but we don't want to spend fuzz budget on it).
    if shares.iter().any(|s| s.payload.len() < payload_len) {
        return;
    }
    let _ = recover_for_fuzz(&shares, payload_len);
});
