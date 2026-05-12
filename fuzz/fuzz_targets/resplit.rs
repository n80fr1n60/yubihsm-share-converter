//! R12-Phase-D / item #6: resplit-target libFuzzer harness.
//!
//! INVARIANT: `resplit::split_with_rng` MUST never panic on any input
//! `(secret, threshold, n, rng)` where the documented preconditions
//! hold (threshold ∈ [2..=31], n ∈ [threshold..=255], `secret`
//! non-empty). This harness derives all of those from fuzz input,
//! clamped to a fuzz-friendly subset that focuses on the production
//! shapes (AES-128/192/256 wrap-blob byte lengths).
//!
//! Coverage target: the per-byte coefficient draw + `eval_poly` loop
//! in `src/resplit.rs::split_with_rng`. The `CryptoRng` bound on the
//! generic parameter type-system-enforces that we can only pass an
//! RNG that satisfies the marker — `ChaCha20Rng` satisfies it (which
//! is sound for FUZZ-deterministic-replay; NOT sound for production
//! splitting, which uses `OsRng` via the `split` shim).

#![no_main]
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use yubihsm_share_converter::resplit::split_with_rng;

fuzz_target!(|data: &[u8]| {
    // Minimum input shape: 32 bytes seed + 2 bytes (threshold + n)
    // + at least 36 bytes (smallest legitimate AES-128 wrap-blob).
    if data.len() < 32 + 2 + 36 {
        return;
    }
    // First 32 bytes = ChaCha20 seed. `ChaCha20Rng::from_seed` is
    // infallible on a fixed-length [u8; 32]; the seed dictates the
    // RNG's full output stream so libFuzzer can shrink replays.
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);
    // Next 2 bytes = threshold + n. Clamp to a fuzz-friendly subset
    // of the production range so we don't spend all fuzz budget on
    // the extremes (which the validate-and-reject branch already
    // covers in unit tests).
    let threshold = 2 + (data[32] % 8); // [2..=9]
    let n_extra = data[33] % (9 - threshold + 1);
    let n = threshold + n_extra; // [threshold..=9]
    // Remaining bytes = blob. Clamp to the legitimate AES wrap-blob
    // range (36..=60 bytes — 20-byte prefix + 16/24/32-byte AES key).
    let blob_bytes = &data[34..];
    let blob_len = blob_bytes.len();
    if !(36..=60).contains(&blob_len) {
        return;
    }
    // Pass blob_bytes directly to split_with_rng — the production
    // signature is `secret: &[u8]`. No `Secret` wrapper needed here;
    // libFuzzer owns the input lifetime.
    let _ = split_with_rng(blob_bytes, threshold, n, &mut rng);
});
