//! Legacy GF(2^8) field with reduction polynomial x^8 + x^4 + x^3 + x^2 + 1
//! (low byte 0x1D) — matches rusty-secrets 0.0.2 so share bytes round-trip.
//!
//! Extracted from `main.rs` in R11/C3 (no behavioural change). Items are
//! `pub` (rather than the previous module-internal visibility) so the
//! `gen_fixture` bin can cross-import via the lib in R11/C3 commit 3.
//!
//! R12-C-04: the cache-timed table-lookup `Tables` struct (log/exp
//! tables + `build_tables` + `xtimes`) was DROPPED from production code.
//! `mul` was already branchless (R11-C2); `inv` is now branchless too via
//! 8-iteration square-and-multiply that exponentiates to `a^254` (= a^-1
//! in GF(2^8), since the multiplicative group has order 255). All call
//! sites lose the `&Tables` arg. The pre-R12 table form is preserved in
//! a `#[cfg(test)] mod tests::reference` block for byte-identical
//! equivalence testing of the new branchless `inv` against the historic
//! implementation.

/// R11-C2: constant-time scalar branchless Russian peasant over the legacy
/// reduction polynomial 0x11D. No branches conditional on bits of `a` or
/// `b`; no table lookups; 8 iterations regardless of inputs.
///
/// R12-C-04: the `_t: &Tables` argument was DROPPED (the `Tables` struct
/// is itself deleted from production code per the same item). `mul` had
/// already stopped consulting the log/exp tables in R11-C2; the only
/// reason the arg lingered was API compatibility. With `inv` now also
/// branchless (`a^254` via square-and-multiply in 8 iterations) the
/// entire legacy module is table-free, and the arg is pure cruft.
///
/// Pre-R11-C2 this was a `t.log[a] + t.log[b] → t.exp[…]` table walk: cache-
/// timed on the input bytes and short-circuited on `a == 0 || b == 0`. The
/// branchless form removes both side channels at no measurable throughput
/// cost — the 8-iteration Russian-peasant runs in single-digit ns on any
/// modern x86_64 and the legacy field is only walked at recover-time, which
/// is bounded by `payload_len ≤ 60` per share-set.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    let mut acc: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1); // 0x00 or 0xFF
        acc ^= mask & a;
        let high = a >> 7;
        let high_mask = 0u8.wrapping_sub(high);
        a = (a << 1) ^ (high_mask & 0x1D);
        b >>= 1;
    }
    acc
}

/// a^-1 = a^254 in GF(2^8). Errors if a == 0 (zero has no
/// multiplicative inverse in any field).
///
/// R12-C-04: branchless square-and-multiply replaces the pre-R12
/// cache-timed `t.exp[(255 - t.log[a]) % 255]` table lookup. The
/// algorithm exploits the fact that the multiplicative group of
/// GF(2^8) has order 255, so `a^255 = 1` for every nonzero a, which
/// implies `a^-1 = a^254`. The exponent 254 = 0b11111110 has 7 set
/// bits (positions 1..=7), so the loop body invokes a `mul`
/// conditionally on each bit of `e` and squares the running base at
/// each iteration — exactly the standard square-and-multiply, but
/// with mask-fold select replacing the bit-conditioned branch.
///
/// The zero-input guard remains a normal early-return: the value
/// `a == 0` is the only domain error, and `inv(0)` is unreachable
/// on the recover() hot path because `Σ y_i · Π_{j≠i} x_j / (x_i ⊕ x_j)`
/// only ever calls `inv` on the Lagrange denominator `Π (x_i ⊕ x_j)`,
/// which is a product of pairwise-distinct Shamir x-coordinates — the
/// surrounding `interp_at[_zero]` duplicate-x rejection in Phase 1
/// guarantees no factor is zero. The guard is therefore a
/// defence-in-depth contract on the function itself: any future
/// caller that passes 0 hits a clear domain error rather than the
/// silent `1` that a careless `a^254` would yield (since `0^254 = 0`,
/// not the inverse of zero — but a brittle caller might still treat
/// `0` as a valid output).
///
/// Constant-time WRT `a`: the loop count (8) and the operations per
/// iteration (one `mul`, one square via `mul(base, base)`, one mask
/// fold, one bit-shift) are independent of `a`. The exponent bits of
/// `e = 254` are public constants of the algorithm, not function of
/// `a`, so even though the mask `0u8.wrapping_sub(e & 1)` derives from
/// `e`, it is the SAME sequence for every input. No data-dependent
/// branch and no table lookup — the only operations on `a` are the
/// branchless `mul` from above.
// R14-v7: `src/legacy.rs:98:32` `| -> ^` is an EQUIVALENT MUTATION.
//
// At line 98, `acc = (mask & product) | (!mask & acc)` -- the two operands
// of `|` are bit-disjoint because `mask` (computed at line 96 as
// `0u8.wrapping_sub(e & 1)` in {0x00, 0xFF}) and `!mask` are complementary:
// `mask & !mask = 0` at every bit position. For bit-disjoint operands,
// `|` and `^` produce byte-identical output (no carry possible; XOR
// matches OR because no bit is set in both operands).
//
// Therefore `(mask & product) | (!mask & acc)` ==
//           `(mask & product) ^ (!mask & acc)` for every input.
//
// The mutation is semantically a no-op -- no test against this structure
// can discriminate the mutated form from the original. The companion
// mutation `| -> &` IS killed by the Fermat-reference test
// (`inv_matches_fermat_table_exhaustive`) because AND of disjoint operands
// is always 0, producing wrong results.
//
// SECOND function-level `#[mutants::skip]` in R14 (FIRST is on the non-
// Linux `assert_single_threaded` variant in src/main.rs). The Fermat-
// reference test still ships and provides exhaustive coverage on the
// other 52 mutants in the legacy.rs module.
//
// `#[cfg_attr(test, mutants::skip)]` gates the attribute on `cfg(test)`
// so release builds remain byte-identical to pre-v2 -- cargo-mutants
// compiles in test mode, so the skip is recognised by the mutation tool
// while production code emits no `mutants` reference at all.
#[cfg_attr(test, mutants::skip)]
#[inline]
pub fn inv(a: u8) -> Result<u8, &'static str> {
    if a == 0 {
        return Err("inv(0): zero has no multiplicative inverse in GF(2^8)");
    }
    // R12-C-04: branchless a^254 via 8-iteration square-and-multiply.
    // e = 254 = 0b11111110. acc accumulates a^(2^i) when bit i of e is set.
    let mut acc: u8 = 1;
    let mut base = a;
    let mut e: u8 = 254;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(e & 1); // 0x00 or 0xFF
        let product = mul(acc, base);
        acc = (mask & product) | (!mask & acc);
        base = mul(base, base);
        e >>= 1;
    }
    Ok(acc)
}

/// Lagrange interpolation at x = 0 over the legacy field.
///
/// R9-H2: accept an iterator-producing closure rather than a slice of
/// (xi, yi) tuples. The legacy field requires two passes (Phase-1
/// validation then Phase-3 Lagrange evaluation); a single-shot
/// Iterator is consumed in one pass, so the API takes a closure that
/// produces a FRESH iterator each call. This pattern is borrowck-
/// friendly (no need to hold a borrowed copy across passes) and
/// avoids any heap allocation in the caller — the previous
/// `&[(u8, u8)]` shape forced callers (notably `recover()`) to
/// materialise per-byte points into a `Vec<(u8, u8)>` that held raw
/// share Y-bytes and was dropped without scrubbing every loop.
///
/// Trait bound: `Fn() -> impl Iterator<Item = (u8, u8)>`. The closure
/// must be callable multiple times because the function performs two
/// independent passes (Phase 1 + Phase 3). `FnOnce` would be a footgun.
///
/// xs holds Shamir x-coordinates (public per design — they appear
/// verbatim in the T-N-base64 share-line format); stack residue on
/// panic-unwind is information-theoretically irrelevant and accepted.
/// Under panic = "abort" (Cargo.toml release profile) the unwind path
/// doesn't exist at all.
///
///   L(0) = Σ y_i · Π_{j≠i} (-x_j) / (x_i - x_j)
///        = Σ y_i · Π_{j≠i}  x_j  / (x_i ⊕ x_j)     [char 2: -a = a]
///
/// R12-C-04: signature drops the `&Tables` arg (Tables struct deleted
/// from production code).
pub fn interp_at_zero<F, I>(points: F) -> Result<u8, String>
where
    F: Fn() -> I,
    I: Iterator<Item = (u8, u8)>,
{
    // Phase 1: x_i == 0 + duplicate-x rejection. Re-create the iterator;
    // collect ONLY the x-coordinates into a stack-resident u8 array
    // bounded by the threshold range [2..31] enforced upstream. The
    // bound permits a fixed-size [u8; 32] scratch so even the x-list
    // never touches the heap.
    let mut xs = [0u8; 32];
    let mut n = 0usize;
    for (xi, _yi) in points() {
        if xi == 0 {
            return Err("share index 0 is invalid in legacy field".into());
        }
        if n >= xs.len() {
            return Err(format!("interpolation set exceeds {}-share cap", xs.len()));
        }
        if xs[..n].contains(&xi) {
            return Err(format!("duplicate x={xi} in interpolation set"));
        }
        xs[n] = xi;
        n += 1;
    }
    // Phase 3: Lagrange evaluation. Re-create the iterator; pair each
    // (xi, yi) with the OTHER xj values from `xs[..n]`.
    let mut sum: u8 = 0;
    for (i, (xi, yi)) in points().enumerate() {
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for (j, &xj) in xs[..n].iter().enumerate() {
            if i == j {
                continue;
            }
            num = mul(num, xj);
            den = mul(den, xi ^ xj);
        }
        let li0 = mul(num, inv(den)?);
        sum ^= mul(yi, li0);
    }
    Ok(sum)
}

/// R4-5: Lagrange interpolation at arbitrary x over the legacy field.
/// Used by the over-determined cross-check at the resplit callsite.
///
/// R9-H2 + R9-v2 M-5: same iterator-closure shape as
/// `interp_at_zero`, but the Item is `(u8, &[u8])` so the caller can
/// borrow each share's payload slice directly (avoiding any per-byte
/// (u8, u8) materialisation). `byte_idx` and `x` remain as separate
/// usize/u8 args — they are public inputs to the over-determined
/// cross-check, not secret-bearing.
///
/// The polynomial is uniquely defined by the points produced by
/// `points()`; caller MUST ensure that the number of points equals
/// `t` (the threshold) and that `x` is NOT one of those indices for
/// genuine over-determined verification (otherwise the result would
/// trivially equal the existing y at that point — Phase 2 covers
/// that case as a correctness-preserving early-return).
///
/// SAFETY (in the documentation sense, not unsafe): caller validates
/// equal payload_len across all shares before reaching this site (see
/// payload-length consistency check at the parse-loop in main()), so
/// `byte_idx < payload.len()` for every share. xs holds Shamir
/// x-coordinates (public per design); stack residue on panic-unwind is
/// information-theoretically irrelevant and accepted.
///
/// Phase 1: full xi==0 + duplicate-x scan (transcribed from
///          `interp_at_zero` — must run BEFORE the early-return below
///          so duplicate-x is detected even if x collides with one of
///          the duplicates).
/// Phase 2: if x collides with a point's xi, return that point's y_byte
///          directly. (This early-return is correctness-preserving
///          for both x==0 and x==xi-for-some-i; it must NOT precede
///          phase 1 or duplicate-x is masked.)
/// Phase 3: Lagrange evaluation: L(x) = Σ y_i · Π_{j≠i} (x ⊕ x_j) / (x_i ⊕ x_j)
///          (in characteristic 2: subtraction = XOR).
///
/// R12-C-04: signature drops the `&Tables` arg (Tables struct deleted
/// from production code).
pub fn interp_at<'a, F, I>(points: F, byte_idx: usize, x: u8) -> Result<u8, String>
where
    F: Fn() -> I,
    I: Iterator<Item = (u8, &'a [u8])>,
{
    // Phase 1: xi == 0 + duplicate-x rejection (identical to
    // interp_at_zero). Re-create the iterator; collect ONLY the
    // x-coordinates into a stack-resident u8 array.
    let mut xs = [0u8; 32];
    let mut n = 0usize;
    for (xi, _payload) in points() {
        if xi == 0 {
            return Err("share index 0 is invalid in legacy field".into());
        }
        if n >= xs.len() {
            return Err(format!("interpolation set exceeds {}-share cap", xs.len()));
        }
        if xs[..n].contains(&xi) {
            return Err(format!("duplicate x={xi} in interpolation set"));
        }
        xs[n] = xi;
        n += 1;
    }
    // Phase 2: collision-with-x early-return (correctness-preserving
    // for x == xi; only legal AFTER phase 1).
    for (xi, payload) in points() {
        if xi == x {
            return Ok(payload[byte_idx]);
        }
    }
    // Phase 3: Lagrange evaluation at arbitrary x.
    let mut sum: u8 = 0;
    for (i, (xi, payload)) in points().enumerate() {
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for (j, &xj) in xs[..n].iter().enumerate() {
            if i == j {
                continue;
            }
            num = mul(num, x ^ xj);
            den = mul(den, xi ^ xj);
        }
        let li_x = mul(num, inv(den)?);
        sum ^= mul(payload[byte_idx], li_x);
    }
    Ok(sum)
}

// ───────────────────────────── tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// R12-C-04: test-only reference implementation of the legacy field
    /// in TABLE-LOOKUP form (the pre-R11-C2 layout: a `log[a]` and
    /// `exp[i]` table built once via repeated `xtimes`). This block
    /// preserves the historical algorithm so the new branchless `inv`
    /// can be tested for byte-identical equivalence across the entire
    /// 256-input domain.
    ///
    /// The struct + builder are intentionally kept INSIDE
    /// `#[cfg(test)]` (so they are NEVER compiled into release builds —
    /// not even as dead code) and their visibility is module-internal
    /// only. Any future caller that tries to use `Tables` outside the
    /// test module hits a `cannot find type` error, which cements the
    /// R12-C-04 production-side drop.
    #[cfg(test)]
    struct ReferenceTables {
        exp: [u8; 256],
        log: [u8; 256],
    }

    /// Multiply-by-x in the legacy field (poly 0x11D). The pre-R12-C-04
    /// production `xtimes`; moved here under `#[cfg(test)]` so it can
    /// still drive `build_reference_tables()` without lingering in
    /// release builds.
    #[cfg(test)]
    fn ref_xtimes(p: u8) -> u8 {
        let high = p >> 7;
        let mask = 0u8.wrapping_sub(high); // 0x00 or 0xFF
        (p << 1) ^ (mask & 0x1D)
    }

    /// Build the log/exp tables. Pre-R12-C-04 production
    /// `build_tables`; moved here under `#[cfg(test)]`.
    #[cfg(test)]
    fn build_reference_tables() -> ReferenceTables {
        let mut t = ReferenceTables {
            exp: [0u8; 256],
            log: [0u8; 256],
        };
        let mut tmp: u8 = 1;
        for power in 0..255 {
            t.exp[power] = tmp;
            t.log[tmp as usize] = power as u8;
            tmp = ref_xtimes(tmp);
        }
        t
    }

    /// R11-C2 reference impl: byte-identical to the pre-R11-C2 `legacy::mul`
    /// body (table-lookup form over poly 0x11D).
    #[cfg(test)]
    fn mul_reference_table_form_0x11d(t: &ReferenceTables, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = t.log[a as usize] as usize;
        let lb = t.log[b as usize] as usize;
        t.exp[(la + lb) % 255]
    }

    /// R12-C-04 reference impl: byte-identical to the pre-R12-C-04
    /// `legacy::inv` body (table-lookup form: a^-1 = exp[255 - log[a]]).
    /// Used by the exhaustive equivalence test against the new
    /// branchless `inv`.
    #[cfg(test)]
    fn ref_inv(t: &ReferenceTables, a: u8) -> Result<u8, &'static str> {
        if a == 0 {
            return Err("inverse of zero in GF(2^8)");
        }
        let la = t.log[a as usize] as usize;
        Ok(t.exp[(255 - la) % 255])
    }

    /// Helper: a^n via repeated `mul` (the production branchless form),
    /// used by the multiplicative-order property test below.
    #[cfg(test)]
    fn pow(a: u8, mut n: u32) -> u8 {
        let mut base = a;
        let mut acc: u8 = 1;
        while n > 0 {
            if n & 1 == 1 {
                acc = mul(acc, base);
            }
            base = mul(base, base);
            n >>= 1;
        }
        acc
    }

    // R12-Phase-D / item #8: 65 536-pair exhaustive walks are far too
    // slow under miri (each `mul` call goes through miri's full
    // interpreter — orders of magnitude slower than native). Gate them
    // out so the miri job stays under the SD-R12-4 5-minute budget.
    // The sampled / corner-case tests below still run under miri, so
    // the algebraic kernels remain miri-validated against UB.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn mul_branchless_matches_reference_exhaustive() {
        // R11-C2 acceptance: the branchless scalar form must be byte-
        // identical to the prior table-lookup form across the ENTIRE
        // (a, b) ∈ u8 × u8 = 65 536 input space. This is the load-bearing
        // regression guard for the constant-time refactor — any deviation
        // (single-bit, single-input) trips here.
        let t = build_reference_tables();
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                let got = mul(a, b);
                let want = mul_reference_table_form_0x11d(&t, a, b);
                assert_eq!(
                    got, want,
                    "legacy::mul branchless diverged from reference at a=0x{a:02x} b=0x{b:02x}"
                );
            }
        }
    }

    #[test]
    fn mul_identity_one_is_neutral() {
        // a · 1 = a and 1 · a = a for every a ∈ u8.
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, 1), a, "a · 1 must equal a at a=0x{a:02x}");
            assert_eq!(mul(1, a), a, "1 · a must equal a at a=0x{a:02x}");
        }
    }

    #[test]
    fn mul_annihilator_zero_is_absorbing() {
        // a · 0 = 0 and 0 · a = 0 for every a ∈ u8.
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, 0), 0, "a · 0 must equal 0 at a=0x{a:02x}");
            assert_eq!(mul(0, a), 0, "0 · a must equal 0 at a=0x{a:02x}");
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn mul_commutativity_exhaustive() {
        // mul(a, b) == mul(b, a) for every (a, b) ∈ u8 × u8.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                assert_eq!(
                    mul(a, b),
                    mul(b, a),
                    "mul is non-commutative at a=0x{a:02x} b=0x{b:02x}"
                );
            }
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn mul_legacy_associativity_exhaustive() {
        // mul(mul(a, b), c) == mul(a, mul(b, c)) for every
        // (a, b, c) ∈ u8 × u8 × u8 — the full 16.7M-triple
        // input space. Discharges in ~1-3 s on a release-profile build
        // (cargo test --release). The polynomial used is the legacy
        // 0x11D reduction (mul body at src/legacy.rs:~120).
        //
        // Load-bearing for the Lagrange recovery at src/legacy.rs:133-175:
        // Σ y_i · Π_{j /= i} x_j relies on the product Π being
        // associative; a non-associative `mul` would yield parenthesisation-
        // dependent values from the same input set.
        //
        // This test is the load-bearing every-push Rust-side defender of
        // associativity post-R18-01 (which moved the Cryptol Z3 :prove
        // mul_legacy_associative to offline-only). Mirrors the spec's
        // `property mul_legacy_associative` at spec/properties.cry:306-308.
        // See R18-03 in FIX_PLAN.html for the v2 rationale.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                for c in 0u16..=255 {
                    let a = a as u8;
                    let b = b as u8;
                    let c = c as u8;
                    assert_eq!(
                        mul(mul(a, b), c),
                        mul(a, mul(b, c)),
                        "mul is non-associative at a=0x{a:02x} b=0x{b:02x} c=0x{c:02x}"
                    );
                }
            }
        }
    }

    #[test]
    fn mul_distributivity_over_xor_sampled() {
        // mul(a, b ⊕ c) == mul(a, b) ⊕ mul(a, c) over selected corner cases
        // + 1024 deterministic pseudo-random triples (xorshift, no external
        // RNG dep).
        let check = |a: u8, b: u8, c: u8| {
            let lhs = mul(a, b ^ c);
            let rhs = mul(a, b) ^ mul(a, c);
            assert_eq!(
                lhs, rhs,
                "distributivity failed at a=0x{a:02x} b=0x{b:02x} c=0x{c:02x}"
            );
        };
        // Corner cases.
        for v in [0u8, 1, 2, 0x1D, 0x80, 0xFE, 0xFF] {
            check(v, 0, 0);
            check(0, v, v);
            check(v, v, v);
            check(v, 0, v);
            check(v, v, 0);
        }
        // 1024 pseudo-random triples (xorshift seeded by a fixed constant).
        let mut state: u32 = 0xDEAD_BEEF;
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
    fn mul_pow_256_eq_a_full_range() {
        // The multiplicative group of GF(2^8) has order 255. So for every
        // nonzero a, a^255 = 1, and consequently a^256 = a. For a = 0,
        // a^256 = 0 (an integer-power-of-0 in the field). Either way,
        // a^256 = a for all a ∈ u8. This is a strong algebraic-closure
        // check on the new branchless `mul` body.
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(pow(a, 256), a, "pow(a, 256) must equal a at a=0x{a:02x}");
        }
        // Bonus: a^255 = 1 for every nonzero a (the order divides 255).
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(pow(a, 255), 1, "pow(a, 255) must equal 1 at a=0x{a:02x}");
        }
    }

    #[test]
    fn mul_legacy_poly_0x57_0x83_yields_0x31() {
        // Cross-poly anchor: under poly 0x11D the product 0x57 · 0x83 is
        // 0x31 — DIFFERENT from the AES-poly-0x11B value of 0xC1 pinned
        // in resplit::tests::mul_aes_aes_poly_0x57_0x83_yields_0xc1. This
        // pair confirms the two polynomials are genuinely distinct and
        // that `legacy::mul` is computing under the LEGACY reduction
        // constant 0x1D, not the AES constant 0x1B. The expected value
        // 0x31 is computed by the reference (table form) implementation,
        // which is byte-for-byte rusty-secrets 0.0.2 compatible — the
        // exhaustive equivalence test above guarantees the branchless
        // form agrees on this input.
        //
        // R12-C-04: `mul` now takes 2 args (the &Tables param was
        // dropped); the anchor numeric value is unchanged.
        assert_eq!(mul(0x57, 0x83), 0x31);
    }

    #[test]
    fn mul_legacy_poly_second_independent_pair() {
        // A second cross-poly anchor with no overlap with the first.
        // 0x80 · 2 in the legacy field reduces by 0x11D → 0x1D (NOT 0x1B,
        // which would be the AES-poly answer). Two independent pinned
        // products jointly determine the reduction constant; together
        // with the 0x57 · 0x83 anchor above, the legacy poly is locked.
        //
        // R12-C-04: 2-arg form, no &Tables.
        assert_eq!(mul(0x80, 2), 0x1D);
    }

    // ───────────────────────── R12-C-04 inv tests ────────────────────────
    //
    // The pre-R12-C-04 `inv` was a single 1-line table lookup whose only
    // (lightweight) test was a 1-line zero-rejection unit test in
    // src/main.rs::tests::inv_zero_errors plus the round-trip property
    // (a · a^-1 = 1) buried inside `legacy_field_basics`. With the body
    // promoted to a branchless 8-iteration square-and-multiply over 254,
    // we now harden the function with the following PROPERTY-BASED
    // crypto coverage:
    //
    //   • exhaustive byte-identical equivalence vs the historic table
    //     reference (256/256 inputs);
    //   • exhaustive multiplicative-inverse round-trip (255 nonzero
    //     inputs, both orderings);
    //   • exhaustive involution (255 nonzero inputs);
    //   • zero-input domain-error message contract;
    //   • two pinned constants (inv(1), inv(2));
    //   • homomorphism inv(a · b) = inv(a) · inv(b) (1024 sampled pairs);
    //   • algorithmic spec: inv(a) equals the slow-pow-254 baseline (255
    //     nonzero inputs);
    //   • two source-form anti-regression greps that lock the Tables drop
    //     and the no-table-lookup-in-inv guarantee.
    //
    // Together they comprehensively pin the new branchless body across
    // ALGEBRAIC properties (group identity, involution, homomorphism) +
    // CRYPTOGRAPHIC equivalence (byte-identical to historical reference) +
    // STRUCTURAL anti-regression (source-form greps). The exhaustive
    // sweeps run in < 100 ms each (256 inputs × O(8) iters × O(1) per
    // mul); the sampled tests run in microseconds.

    // R12-Phase-D / item #8: also too slow under miri (the
    // reference-table builder calls `mul` 510 times to populate
    // log/exp tables, then `inv` calls `mul` 8 times per input; with
    // miri's per-op overhead the test approaches the 5-minute budget
    // on its own). Sampled tests cover the algorithmic surface.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn inv_branchless_matches_reference_exhaustive() {
        // R12-C-04 ACCEPTANCE: the branchless square-and-multiply form
        // of `inv` must be byte-identical to the prior table-lookup form
        // across the ENTIRE u8 input space. Both implementations must
        // ALSO agree on the zero-input error path (both return `Err(_)`,
        // though the precise error message strings differ — that's by
        // design: the new body's message is more specific).
        let t = build_reference_tables();
        for a in 0u16..=255 {
            let a = a as u8;
            let got = inv(a);
            let want = ref_inv(&t, a);
            match (got, want) {
                (Ok(g), Ok(w)) => assert_eq!(
                    g, w,
                    "inv branchless diverged from reference at a=0x{a:02x}: got 0x{g:02x}, want 0x{w:02x}"
                ),
                (Err(_), Err(_)) => {
                    // Both error on a==0; message strings are allowed to
                    // differ (the new message is "inv(0): zero has no
                    // multiplicative inverse in GF(2^8)" vs the historic
                    // "inverse of zero in GF(2^8)"). The CONTRACT is that
                    // both reject `0`; the human-readable wording is not
                    // part of the contract.
                    assert_eq!(a, 0, "Err returned for nonzero a=0x{a:02x}");
                }
                (g, w) => panic!(
                    "inv divergence at a=0x{a:02x}: branchless={g:?} reference={w:?}"
                ),
            }
        }
    }

    #[test]
    fn inv_is_multiplicative_inverse_exhaustive() {
        // For every nonzero a ∈ {1, .., 255}: a · a^-1 = 1 and
        // a^-1 · a = 1 (commutativity is independently tested above; we
        // assert both orderings here for defence-in-depth — a subtle bug
        // in `inv` that happened to produce a left-but-not-right inverse
        // would be caught by either branch in isolation).
        for a in 1u16..=255 {
            let a = a as u8;
            let ai = inv(a).expect("nonzero a must have an inverse");
            assert_eq!(
                mul(a, ai),
                1,
                "mul(a, inv(a)) must equal 1 at a=0x{a:02x} (got 0x{:02x})",
                mul(a, ai)
            );
            assert_eq!(mul(ai, a), 1, "mul(inv(a), a) must equal 1 at a=0x{a:02x}");
        }
    }

    #[test]
    fn inv_is_involution() {
        // (a^-1)^-1 = a for every nonzero a. Together with the
        // multiplicative-inverse test above, this pins inv as a
        // genuine group-theoretic inverse of order 2 in the
        // permutation group on the nonzero elements (every element
        // is its own preimage under the inv function).
        for a in 1u16..=255 {
            let a = a as u8;
            let ai = inv(a).expect("nonzero a must invert");
            let aii = inv(ai).expect("nonzero ai must invert");
            assert_eq!(
                aii, a,
                "inv(inv(a)) must equal a at a=0x{a:02x} (got 0x{aii:02x})"
            );
        }
    }

    #[test]
    fn inv_zero_returns_err() {
        // The zero-input guard returns Err(_). The error message MUST
        // mention "inv(0)" or "zero" so an operator triaging the failure
        // can immediately identify the root cause. (The exact message
        // string is intentionally NOT pinned — only its content
        // discipline — to leave room for future wording updates.)
        let err = inv(0).expect_err("inv(0) must error");
        assert!(
            err.contains("inv(0)") || err.contains("zero"),
            "inv(0) error message must mention inv(0) or zero; got: {err:?}"
        );
    }

    #[test]
    fn inv_of_one_is_one() {
        // The multiplicative identity is its own inverse. This is a
        // trivial corollary of `1 · 1 = 1` but is asserted here as a
        // single-byte sanity anchor: any algorithm that derived `inv`
        // from a wrong basis (e.g. additive inverse, which is the
        // identity in characteristic 2 → would still give inv(1) = 1
        // accidentally) would still need to pass this check.
        assert_eq!(inv(1), Ok(1));
    }

    #[test]
    fn inv_of_two_known_value() {
        // Pin inv(2) to the historical-reference value. In the legacy
        // field (poly 0x11D), the inverse of 2 is precisely 0x8E (verified
        // by the byte-identical exhaustive test above; the value is
        // also computable by hand: in any field of characteristic 2 the
        // inverse of the generator x is x^254 reduced by the irreducible
        // polynomial; for poly 0x11D the answer is 0x8E). Anchoring two
        // concrete values (inv(1) above and inv(2) here) defends against
        // a regression that off-by-one'd the exponent (e.g. a^253 or
        // a^255 would produce different values at this input).
        let t = build_reference_tables();
        // Compute the expected value from the reference impl so the
        // anchor self-validates if someone questions the literal.
        let want = ref_inv(&t, 2).expect("inv(2) is defined");
        assert_eq!(
            inv(2),
            Ok(want),
            "inv(2) must match historic table value (= 0x{want:02x})"
        );
        // Sanity: the historical value is indeed 0x8E.
        assert_eq!(want, 0x8E, "inv(2) under poly 0x11D is 0x8E (historic)");
    }

    #[test]
    fn inv_distributes_with_mul_sampled() {
        // The multiplicative-group homomorphism property:
        //     inv(a · b) = inv(a) · inv(b)         for every nonzero a, b.
        // This is the SIGNATURE algebraic identity that distinguishes a
        // genuine field inverse from a pseudo-inverse table; a hand-coded
        // implementation that quietly swapped a^254 for some unrelated
        // permutation would fail this test even if it happened to round-
        // trip mul(a, inv(a)) at a single point.
        //
        // Sample 1024 (a, b) pairs from a deterministic xorshift PRNG so
        // the test is reproducible. Discard zero inputs (no inverse).
        let mut state: u32 = 0x5EED_C0DE;
        let mut tested = 0u32;
        let mut attempts = 0u32;
        while tested < 1024 && attempts < 10_000 {
            attempts += 1;
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let a = state as u8;
            let b = (state >> 8) as u8;
            if a == 0 || b == 0 {
                continue;
            }
            let lhs = inv(mul(a, b)).expect("mul of two nonzero is nonzero in a field");
            let rhs = mul(inv(a).unwrap(), inv(b).unwrap());
            assert_eq!(
                lhs, rhs,
                "homomorphism failed: inv({a:02x} · {b:02x}) = {lhs:02x}, inv·inv = {rhs:02x}"
            );
            tested += 1;
        }
        assert!(
            tested == 1024,
            "sampled inv-homomorphism test must reach 1024 pairs (got {tested})"
        );
    }

    #[test]
    fn inv_consistent_with_pow_254_via_square_and_multiply() {
        // The algorithmic spec for `inv` is `a -> a^254`. We verify
        // this with an INDEPENDENT slow-pow baseline — 253 iterations
        // of `mul(acc, a)` starting from acc=a, which by construction
        // computes a · a · ... · a = a^254. Any algorithmic regression
        // in the new branchless body (e.g. off-by-one on the exponent,
        // wrong shift direction, mask polarity inversion) trips here.
        for a in 1u16..=255 {
            let a = a as u8;
            // Slow baseline: a^254 via 253 multiplications (a × a^253).
            let mut acc: u8 = a;
            for _ in 1..254 {
                acc = mul(acc, a);
            }
            let slow = acc; // = a^254
            let fast = inv(a).expect("nonzero a must invert");
            assert_eq!(
                fast, slow,
                "inv(a) must equal a^254 at a=0x{a:02x} (fast=0x{fast:02x} slow=0x{slow:02x})"
            );
        }
    }

    // ────────────────────────── R14-01 Fermat reference ──────────────────────
    //
    // The `inv_branchless_matches_reference_exhaustive` test above (line 541)
    // compares production `inv` against the historical table-form `ref_inv`,
    // but cargo-mutants reports the mutant `src/legacy.rs:98:32: replace
    // | with ^ in inv` SURVIVES that test. R14-01 investigation finding
    // (see docs/R14-INVESTIGATION.md):
    //
    //   The mask at line 96 (`0u8.wrapping_sub(e & 1)`) is ALWAYS in
    //   {0x00, 0xFF}, so `(mask & product)` and `(!mask & acc)` are
    //   byte-disjoint at every bit position — one is 0 wherever the
    //   other is nonzero. For byte-disjoint operands `(x | y) == (x ^ y)`,
    //   so the `|` -> `^` mutation is MATHEMATICALLY EQUIVALENT under the
    //   current disjoint-mask invariant. The mutant cannot be killed by
    //   any output-comparing test on the current production code.
    //
    // The locked path (per the maintainer decision in FIX_PLAN.html
    // §R14-01): land a structurally-independent Fermat-reference test
    // ANYWAY. It does NOT kill the equivalent mutant on the current
    // production form, but it provides FUTURE-PROOFING: any future
    // refactor of `inv` that drops the disjoint-mask invariant (e.g. a
    // SIMD-style implementation where `mask` overlaps with `!mask`)
    // would make `|` vs `^` semantically distinct, and THIS test (along
    // with the other algebraic property tests) would catch the
    // regression. The test is layered with the existing tests:
    //
    //   • mul     ↔ table-form reference (R11-C2, exhaustive 65 536 pairs)
    //   • inv     ↔ table-form reference (R12-C-04, exhaustive 256 inputs)
    //   • inv     ↔ Fermat reference     (R14-01, exhaustive 255 nonzero)
    //
    // The Fermat reference is built via `inv_fermat`: it computes
    // `a^254` by FLAT REPEATED MULTIPLICATION using the production
    // `mul`, NOT by square-and-multiply. The control structure is
    // genuinely independent of `inv`'s 8-iteration bit-walk.

    /// R14-01: independent reference for `inv` via Fermat's little theorem.
    /// In GF(2^8)\{0}, the multiplicative group has order 255, so
    /// `a^(2^8 - 1) = a^255 = 1`, hence `inv(a) = a^254`.
    ///
    /// Computed via FLAT REPEATED MULTIPLICATION using the production
    /// `mul`, deliberately NOT via square-and-multiply. The loop body
    /// has no bit-walk, no mask construction, and no select operation —
    /// none of the operations in production `inv`'s body appear here.
    /// This gives a control-structure-independent reference that catches
    /// any future mutation to `inv`'s bit-walk that breaks the
    /// disjoint-mask invariant (e.g. the `|` -> `^` mutant at
    /// src/legacy.rs:98:32 would diverge under a non-disjoint mask).
    ///
    /// Constant-time WRT `a`: 254 unconditional `mul` calls; the loop
    /// iteration count is fixed and independent of `a`. The production
    /// `inv` is also constant-time (8-iteration square-and-multiply
    /// independent of `a`; see R12-C-04 commentary on `inv`). Both are
    /// input-independent in iteration count by construction.
    #[cfg(test)]
    fn inv_fermat(a: u8) -> Option<u8> {
        if a == 0 {
            return None;
        }
        // a^254 via 254 multiplications of `a`, starting from acc = 1.
        // After the loop: acc = 1 * a * a * ... * a (254 factors) = a^254.
        let mut acc: u8 = 1;
        for _ in 0..254 {
            acc = mul(acc, a);
        }
        Some(acc)
    }

    /// R14-01: build the full 256-entry Fermat inverse table at test
    /// time. Entry [0] is unused (production `inv(0)` errors and so
    /// does `inv_fermat(0)`); entries [1..256] are the Fermat
    /// inverses computed once per test run.
    #[cfg(test)]
    fn build_inv_fermat_table() -> [u8; 256] {
        let mut t = [0u8; 256];
        for a in 1u16..=255 {
            let a = a as u8;
            t[a as usize] = inv_fermat(a).expect("a != 0");
        }
        t
    }

    // R14-01: 254 muls × 255 inputs ≈ 65k mul calls. Release-mode this
    // completes in well under a second; under miri it would dominate
    // the 5-minute budget (same precedent as the table-form test).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn inv_matches_fermat_table_exhaustive() {
        // Anchor: inv(0x02) MUST equal 0x8E in GF(2^8) under poly 0x11D.
        // This is the value already pinned by `inv_of_two_known_value`
        // above (verified against the historical table reference) and is
        // load-bearing for catching loop-bound off-by-ones: if the
        // Fermat loop ran 253 or 255 times instead of 254, this anchor
        // would fail.
        //
        // NOTE on the anchor value: 0x8E is the inverse of 0x02 under
        // the LEGACY poly 0x11D (the rusty-secrets 0.0.2 reduction
        // polynomial). The AES poly 0x11B gives 0x8D — the canonical
        // FIPS-197 value — but THIS file is the legacy field, not AES.
        // Do not confuse the two: cross-poly mismatches surface here
        // as well, so this anchor doubles as a poly-identity pin.
        assert_eq!(
            inv(0x02),
            Ok(0x8E),
            "production inv anchor failed: inv(0x02) must equal 0x8E under poly 0x11D"
        );
        assert_eq!(
            inv_fermat(0x02),
            Some(0x8E),
            "Fermat reference anchor failed: inv_fermat(0x02) must equal 0x8E under poly 0x11D"
        );

        // Exhaustive: for all 255 nonzero a, production `inv` must agree
        // with the structurally-independent Fermat reference.
        //
        // NOTE: under the current disjoint-mask invariant at line 96
        // (mask ∈ {0x00, 0xFF}), the `|` -> `^` mutant at line 98:32 is
        // MATHEMATICALLY EQUIVALENT and the production output is
        // byte-identical with or without the mutation — so this test
        // CANNOT kill that specific mutant on the current source. It
        // does, however, future-proof against any refactor that breaks
        // the disjoint-mask invariant, and it adds a third independent
        // reference (alongside the table form and the existing
        // pow-via-flat-loop test) for catching algorithmic regressions
        // in `inv` more broadly. See docs/R14-INVESTIGATION.md for the
        // full write-up.
        let t = build_inv_fermat_table();
        for a in 1u16..=255 {
            let a = a as u8;
            let got = inv(a).expect("a != 0; inv is total on nonzero");
            let want = t[a as usize];
            assert_eq!(
                got, want,
                "inv vs Fermat reference diverged at a=0x{a:02x}: got 0x{got:02x}, want 0x{want:02x}"
            );
        }
    }

    #[test]
    fn inv_no_table_lookup_in_body_grep() {
        // R12-C-04 STRUCTURAL anti-regression: a future refactor that
        // accidentally reintroduces a `Tables` / `t.log[...]` /
        // `t.exp[...]` cache-timed lookup in the `inv` function body
        // would silently undo the constant-time guarantee. Defend
        // against it with a source-form grep that scans this very file
        // (via include_str!).
        //
        // The check is: between `pub fn inv` and the next `}` at column
        // 0 (the function end), neither `t.log` nor `t.exp` appears.
        // We use a forgiving substring scan (no full Rust parser) — any
        // future reintroduction of either substring trips this test
        // even if it's only in a comment, which is fine: the comment
        // itself signals the algorithmic regression.
        let src = include_str!("legacy.rs");
        let body_start = src
            .find("pub fn inv(a: u8) -> Result<u8, &'static str> {")
            .expect("inv function definition must be present at known signature");
        // Find the next "\npub fn " (start of subsequent function) — that
        // delimits the inv body. There IS one (interp_at_zero follows).
        let after = &src[body_start..];
        let next_pub_fn = after[1..]
            .find("\npub fn ")
            .expect("inv must be followed by another pub fn in this module");
        let body = &after[..=next_pub_fn]; // inclusive
        assert!(
            !body.contains("t.log"),
            "regression: inv body contains `t.log[...]` table lookup (R12-C-04 forbids)"
        );
        assert!(
            !body.contains("t.exp"),
            "regression: inv body contains `t.exp[...]` table lookup (R12-C-04 forbids)"
        );
        // Also assert the body contains the load-bearing branchless
        // idiom — a positive presence check, so a refactor that
        // accidentally replaced the loop with SOMETHING ELSE entirely
        // is caught even if it doesn't reintroduce a table lookup.
        assert!(
            body.contains("square-and-multiply") || body.contains("wrapping_sub"),
            "inv body must contain the branchless square-and-multiply idiom"
        );
    }

    #[test]
    fn tables_struct_deleted_grep() {
        // R12-C-04 LOCK-IN: the `pub struct Tables`, `pub fn build_tables`,
        // and `pub fn xtimes` MUST NOT appear in production code (anywhere
        // in this file OUTSIDE the `#[cfg(test)] mod tests { ... }`
        // block). We assert this via include_str!. The test-only
        // reference impl uses different names (`ReferenceTables`,
        // `build_reference_tables`, `ref_xtimes`, `ref_inv`) so it does
        // NOT match the production-shape patterns.
        let src = include_str!("legacy.rs");
        // Production code is everything BEFORE the `mod tests {`. We
        // split there.
        let split_marker = "#[cfg(test)]\nmod tests {";
        let split_at = src
            .find(split_marker)
            .expect("legacy.rs must contain the tests module");
        let production = &src[..split_at];

        assert!(
            !production.contains("pub struct Tables"),
            "regression: production code contains `pub struct Tables` (R12-C-04 forbids)"
        );
        assert!(
            !production.contains("pub fn build_tables"),
            "regression: production code contains `pub fn build_tables` (R12-C-04 forbids)"
        );
        assert!(
            !production.contains("pub fn xtimes"),
            "regression: production code contains `pub fn xtimes` (R12-C-04 forbids)"
        );
        // Also assert that production code contains NO struct named
        // Tables under any visibility (catch a future `pub(crate) struct
        // Tables` or `struct Tables` private fallback).
        assert!(
            !production.contains("struct Tables"),
            "regression: production code contains `struct Tables` of any visibility"
        );
    }

    #[test]
    fn mul_signature_no_tables_arg() {
        // R12-C-04 SIGNATURE LOCK: `mul` must take exactly two `u8` args
        // and return `u8`. If a future refactor reintroduces a leading
        // `&Tables` argument (cf. the pre-R12-C-04 shape), THIS
        // compile-time call site fails to typecheck — the test is a
        // compile-and-run anti-regression guard. The 0x57 · 0x83 = 0x31
        // anchor doubles as a behavioural lock (legacy poly 0x11D).
        assert_eq!(mul(0x57, 0x83), 0x31);
        // And inv must take exactly one u8 → Result<u8, _>:
        assert_eq!(inv(0x57), inv(0x57));
        // Compile-time-only: if `inv` ever takes (&Tables, u8) again the
        // call site `inv(0x57)` here will fail with "this function takes
        // 2 arguments but 1 argument was supplied".
    }

    #[test]
    fn legacy_field_basics_post_drop() {
        // R12-C-04: the pre-R12 `legacy_field_basics` test in
        // src/main.rs::tests still runs against the new signatures (it
        // was updated as part of this commit). Re-pin the same anchors
        // here, INSIDE the legacy module's test block, so a regression
        // is caught at the lowest possible scope (no main.rs harness
        // needed). The values are identical to the historical pre-R12
        // anchors — only the call-site shape changed.
        // 2 · 2 = 4 (no reduction needed; 2·2 = 4 < 0x100).
        assert_eq!(mul(2, 2), 4);
        // 0x80 · 2 = 0x1D (reduction triggers; legacy poly 0x11D).
        assert_eq!(mul(0x80, 2), 0x1D);
        // Every nonzero a has a multiplicative inverse.
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a).unwrap()), 1, "fail at a={a}");
        }
    }

    // ─── R12-C-04 / R11-C2: cross-property identity tests (defence in depth) ───

    #[test]
    fn inv_mul_round_trip_via_two_independent_paths() {
        // For every nonzero (a, b): mul(a, inv(b)) == mul(a, b)^? — wait,
        // the LOAD-BEARING identity here is mul(a, b) · inv(b) = a (left
        // inverse of b cancels). Sample 256 deterministic pairs.
        let mut state: u32 = 0xBEEF_CAFE;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let a = state as u8;
            let mut b = (state >> 8) as u8;
            if b == 0 {
                b = 1; // re-seed to a nonzero value, preserving randomness mod nonzero
            }
            let prod = mul(a, b);
            let recovered = mul(prod, inv(b).unwrap());
            assert_eq!(
                recovered, a,
                "(a · b) · b^-1 must recover a at a=0x{a:02x} b=0x{b:02x} (got 0x{recovered:02x})"
            );
        }
    }
}
