//! Hand-rolled GF(2^8)/poly-0x11B Shamir split (yubihsm-manager
//! `aes_share_validator` wire format).
//!
//! Extracted from `main.rs` in R11/C3 (no behavioural change).

use crate::secret::Secret;
use rand::{CryptoRng, Rng, RngCore};
use zeroize::Zeroize; // R9-v2 B5: needed for buf.zeroize() below.

/// Multiply-by-x in GF(2^8) reducing modulo 0x11B (AES/Rijndael poly).
/// Branchless even before R11-C2 (high-bit mask form). R11-C2 inlined this
/// step into `mul_aes` body to avoid a separate call; the standalone
/// function is retained under `#[cfg(test)]` so test code can still
/// reference the historical idiom without dragging a dead symbol into
/// release builds (which would trip `clippy -D warnings`).
#[cfg(test)]
#[inline]
fn xtimes_aes(p: u8) -> u8 {
    let high = p >> 7;
    let mask = 0u8.wrapping_sub(high); // 0x00 or 0xFF
    (p << 1) ^ (mask & 0x1B)
}

/// GF(2^8) multiply using the AES reduction. R11-C2: constant-time scalar
/// branchless Russian peasant over the AES/Rijndael polynomial 0x11B. No
/// branches conditional on bits of `a` or `b`; no table lookups; 8
/// iterations regardless of inputs.
///
/// Pre-R11-C2 the inner XOR step was guarded by `if b & 1 != 0 { result ^= a; }`,
/// which branched on the value of `b`. Even though `b` is the public share
/// x-coordinate in the production `eval_poly` call shape (so the branch
/// leaks only public bits), the conditional form was a defence-in-depth
/// liability: any future caller that supplied a secret-bearing `b` would
/// silently inherit a timing side channel. The branchless mask form below
/// removes the side channel unconditionally, at zero throughput cost — the
/// function is still O(8) per call (~1620 mul_aes for a 36-byte payload ×
/// 9 shares × 5 threshold ≈ ≤ 1 ms total per resplit).
#[inline]
pub fn mul_aes(a: u8, b: u8) -> u8 {
    let mut acc: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1); // 0x00 or 0xFF
        acc ^= mask & a;
        let high = a >> 7;
        let high_mask = 0u8.wrapping_sub(high);
        a = (a << 1) ^ (high_mask & 0x1B);
        b >>= 1;
    }
    acc
}

/// Evaluate the polynomial defined by `[secret_byte, coeffs[0], coeffs[1], ...]`
/// at x using Horner's rule. `coeffs.len() == threshold - 1`.
#[inline]
fn eval_poly(secret_byte: u8, coeffs: &[u8], x: u8) -> u8 {
    // Horner: p(x) = ((c_{t-1} * x + c_{t-2}) * x + ... + c_1) * x + secret_byte
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = mul_aes(acc, x) ^ c;
    }
    mul_aes(acc, x) ^ secret_byte
}

/// Shamir split. Returns `Vec<Secret>` — one Secret per share, where
/// share i holds [i, p_0(i), p_1(i), ..., p_{L-1}(i)] for L = secret.len().
/// The per-byte coefficient Secret is RE-ALLOCATED each byte iteration
/// (B1: Secret has no `clear()`; reallocation + Drop is the API-shaped
/// way to discard old coefficients between byte positions).
///
/// Caller (the resplit branch in main()) consumes the returned Vec by
/// value via `.drain(..)` so each per-share Secret is Drop'd (and
/// zeroized) on its way out (B3).
///
/// R9-H3 SAFETY: all secret-bearing storage is `Secret`-owned, which
/// means page-aligned + MADV_DONTDUMP'd + zeroed-on-drop. There is no
/// `Vec<u8>` or `[u8; N]` stack-resident transient that holds a share
/// Y-byte without being zeroized on the same function exit. The
/// `share_x` stack value (1..=n) is a *public* Shamir x-coordinate and
/// is information-theoretically irrelevant; it is not protected.
pub fn split(secret: &[u8], threshold: u8, n: u8) -> Result<Vec<Secret>, String> {
    // Production thin-shim around `split_with_rng`. Uses `OsRng` — the
    // OS-backed CSPRNG — which is the only RNG that is sound for
    // production Shamir splitting (any deterministic RNG would make all
    // shares reconstructible from a known seed, which is a fatal
    // confidentiality failure). The `CryptoRng` bound on
    // `split_with_rng` is the type-system enforcement of this contract:
    // a future caller that tried to pass a `rand::rngs::StdRng` (or any
    // other non-`CryptoRng`) would fail to compile.
    let mut rng = rand::rngs::OsRng;
    split_with_rng(secret, threshold, n, &mut rng)
}

/// R12-Phase-D / item #6: fuzz-only RNG seam. Production callers use
/// `split` which delegates here with `OsRng`. The `CryptoRng` bound
/// type-system-enforces that misconfigured downstream callers cannot
/// pass a weak RNG — only RNGs that explicitly opt into the
/// `rand::CryptoRng` marker are accepted.
///
/// The fuzz harness in `fuzz/fuzz_targets/resplit.rs` uses a
/// `ChaCha20Rng` seeded from fuzz input. `ChaCha20Rng` implements
/// `CryptoRng`, so the bound holds; the seed-from-fuzz-input is sound
/// for FUZZ purposes (the RNG output is deterministic per seed, which
/// is exactly what libFuzzer needs for corpus minimisation) but NOT
/// sound for production splitting.
///
/// Behaviour: byte-identical to the pre-R12-Phase-D `split` body, with
/// the internal `rng` binding promoted to a generic parameter. The
/// `threshold`/`n`/`secret` validation runs unchanged so a fuzz input
/// that passes a degenerate combination is rejected via the same error
/// strings the production path uses.
pub fn split_with_rng<R: RngCore + CryptoRng>(
    secret: &[u8],
    threshold: u8,
    n: u8,
    rng: &mut R,
) -> Result<Vec<Secret>, String> {
    if !(2..=31).contains(&threshold) {
        return Err(format!(
            "threshold {threshold} outside legal range [2..=31]"
        ));
    }
    if !(threshold..=255).contains(&n) {
        return Err(format!(
            "share count n={n} outside legal range [{threshold}..=255]"
        ));
    }
    if secret.is_empty() {
        return Err("cannot split empty secret".into());
    }
    // Per-share output: each Secret holds [idx_byte | y_0 | y_1 | ... | y_{L-1}].
    // idx_byte is the public Shamir x-coordinate (1..=n); the y's are secret.
    let mut shares: Vec<Secret> = (1..=n)
        .map(|idx| {
            let mut s = Secret::with_capacity(1 + secret.len());
            s.extend_from_slice(&[idx]); // share_x = idx; written once.
            s
        })
        .collect();
    // For each byte position of the secret, freshly allocate a Secret-
    // backed coefficient buffer, draw threshold-1 random bytes from the
    // caller-supplied RNG, evaluate the polynomial at each share's
    // x-coordinate, and append the y-byte to that share's Secret. The
    // coeffs Secret is re-bound on every iteration; the prior binding's
    // Drop runs at shadow-rebind and zeroizes the old coefficient bytes
    // (B1).
    for &secret_byte in secret.iter() {
        // R9-v2 B1: re-allocate; previous coeffs Secret Drops here.
        let mut coeffs = Secret::with_capacity((threshold - 1) as usize);
        for _ in 0..(threshold - 1) {
            let mut buf = [0u8; 1];
            rng.fill(&mut buf);
            coeffs.extend_from_slice(&buf);
            buf.zeroize();
        }
        // Evaluate at each share index. share_x is recomputed from the
        // iteration index — public per design — instead of read back
        // from share.as_slice()[0] (M-6 simplification).
        for (idx0, share) in shares.iter_mut().enumerate() {
            let share_x = (idx0 as u8) + 1;
            let y = eval_poly(secret_byte, coeffs.as_slice(), share_x);
            share.extend_from_slice(&[y]);
        }
        // coeffs Secret Drops here at end of iteration body → zeroize.
    }
    Ok(shares)
}

// ───────────────────────────── tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// R11-C2 reference impl: byte-identical to the pre-R11-C2 `mul_aes`
    /// body (Russian-peasant 8-iteration with conditional `if b & 1 != 0`
    /// XOR over poly 0x11B). Kept module-local under `#[cfg(test)]` so the
    /// exhaustive equivalence test in `mul_branchless_matches_reference_
    /// exhaustive` can compare every `(a, b) ∈ u8 × u8` input pair against
    /// the historic branch form. Touching this function without updating
    /// the new `mul_aes` body would surface as a hard regression in that
    /// exhaustive test.
    #[cfg(test)]
    fn mul_aes_reference_branch_form_0x11b(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;
        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            a = xtimes_aes(a);
            b >>= 1;
        }
        result
    }

    /// Helper: a^n via repeated `mul_aes` (the production branchless
    /// form), used by the multiplicative-order property test below.
    #[cfg(test)]
    fn pow_aes(a: u8, mut n: u32) -> u8 {
        let mut base = a;
        let mut acc: u8 = 1;
        while n > 0 {
            if n & 1 == 1 {
                acc = mul_aes(acc, base);
            }
            base = mul_aes(base, base);
            n >>= 1;
        }
        acc
    }

    // R12-Phase-D / item #8: 65 536-pair exhaustive walk is too slow
    // under miri; gate it out so the miri job stays under the
    // SD-R12-4 5-minute budget. Sampled tests cover the algorithmic
    // surface; native cargo test still exercises this exhaustive walk.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn mul_branchless_matches_reference_exhaustive() {
        // R11-C2 acceptance: the branchless scalar form must be byte-
        // identical to the prior conditional-branch form across the
        // ENTIRE (a, b) ∈ u8 × u8 = 65 536 input space. This is the
        // load-bearing regression guard for the constant-time refactor
        // — any deviation (single-bit, single-input) trips here.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                let got = mul_aes(a, b);
                let want = mul_aes_reference_branch_form_0x11b(a, b);
                assert_eq!(
                    got, want,
                    "resplit::mul_aes branchless diverged from reference at a=0x{a:02x} b=0x{b:02x}"
                );
            }
        }
    }

    #[test]
    fn mul_aes_identity_one_is_neutral() {
        // a · 1 = a and 1 · a = a for every a ∈ u8.
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(mul_aes(a, 1), a, "a · 1 must equal a at a=0x{a:02x}");
            assert_eq!(mul_aes(1, a), a, "1 · a must equal a at a=0x{a:02x}");
        }
    }

    #[test]
    fn mul_aes_annihilator_zero_is_absorbing() {
        // a · 0 = 0 and 0 · a = 0 for every a ∈ u8.
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(mul_aes(a, 0), 0, "a · 0 must equal 0 at a=0x{a:02x}");
            assert_eq!(mul_aes(0, a), 0, "0 · a must equal 0 at a=0x{a:02x}");
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn mul_aes_commutativity_exhaustive() {
        // mul_aes(a, b) == mul_aes(b, a) for every (a, b) ∈ u8 × u8.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                assert_eq!(
                    mul_aes(a, b),
                    mul_aes(b, a),
                    "mul_aes is non-commutative at a=0x{a:02x} b=0x{b:02x}"
                );
            }
        }
    }

    #[test]
    fn mul_aes_distributivity_over_xor_sampled() {
        // mul_aes(a, b ⊕ c) == mul_aes(a, b) ⊕ mul_aes(a, c) over selected
        // corner cases + 1024 deterministic pseudo-random triples
        // (xorshift, no external RNG dep).
        let check = |a: u8, b: u8, c: u8| {
            let lhs = mul_aes(a, b ^ c);
            let rhs = mul_aes(a, b) ^ mul_aes(a, c);
            assert_eq!(
                lhs, rhs,
                "distributivity failed at a=0x{a:02x} b=0x{b:02x} c=0x{c:02x}"
            );
        };
        // Corner cases.
        for v in [0u8, 1, 2, 0x1B, 0x57, 0x83, 0x80, 0xFE, 0xFF] {
            check(v, 0, 0);
            check(0, v, v);
            check(v, v, v);
            check(v, 0, v);
            check(v, v, 0);
        }
        // 1024 pseudo-random triples (xorshift seeded by a fixed constant).
        let mut state: u32 = 0xCAFE_BABE;
        for _ in 0..1024 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let a = state as u8;
            let b = (state >> 8) as u8;
            let c = (state >> 16) as u8;
            check(a, b, c);
        }
    }

    #[test]
    fn mul_aes_pow_256_eq_a_full_range() {
        // The multiplicative group of GF(2^8) has order 255. So for every
        // nonzero a, a^255 = 1, and consequently a^256 = a. For a = 0,
        // a^256 = 0. Either way, a^256 = a for all a ∈ u8. This is a
        // strong algebraic-closure check on the new branchless `mul_aes`
        // body — equivalent to walking the full multiplicative group once.
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(
                pow_aes(a, 256),
                a,
                "pow(a, 256) must equal a at a=0x{a:02x}"
            );
        }
        // Bonus: a^255 = 1 for every nonzero a (the order divides 255).
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(
                pow_aes(a, 255),
                1,
                "pow(a, 255) must equal 1 at a=0x{a:02x}"
            );
        }
    }

    #[test]
    fn mul_aes_aes_poly_0x57_0x83_yields_0xc1() {
        // R11-C2: FIPS-197 §4.2.1 anchor mirrored at the module level
        // (the matching test in src/main.rs::tests was authored before
        // mod resplit had its own #[cfg(test)] block). Under poly 0x11B,
        // 0x57 · 0x83 = 0xC1 — DIFFERENT from the legacy-poly-0x11D value
        // 0x31 pinned in legacy::tests. Together with the second
        // independent pair below, this locks the AES reduction constant.
        assert_eq!(mul_aes(0x57, 0x83), 0xC1);
    }

    #[test]
    fn mul_aes_aes_poly_second_independent_pair() {
        // Second independent FIPS-anchored pair: 0x57 · 0x13 = 0xFE under
        // poly 0x11B (computed by hand: 0x57 · 0x13 = 0x57 ⊕ 0x57·2 ⊕
        // 0x57·16 = 0x57 ⊕ 0xAE ⊕ 0x07 = 0xFE). Two independent pinned
        // products jointly determine the irreducible polynomial.
        assert_eq!(mul_aes(0x57, 0x13), 0xFE);
    }
}
