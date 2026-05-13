# Formal Cryptol specification — GF(2^8) + Lagrange recovery

This directory hosts the **machine-checked formal specification** of the
cryptographic kernels in `yubihsm-share-converter`. The `.cry` files
under this directory are Cryptol modules; the load-bearing claim is
that every cryptographic operation in `src/legacy.rs` and
`src/resplit.rs` has an algebraic-spec twin here, and the
universally-quantified GF/inversion properties of those twins are
**machine-proven** via Z3 in CI on every push. The heavier Lagrange
obligations are kept as explicit local/offline checks.

## Quick start

The canonical local-run entry point for the CI-safe Cryptol property bundle is
the R13-F top-level proof-runner wrapper:

```bash
bash scripts/run-proofs.sh cryptol
```

The wrapper reads the pinned Cryptol Docker image digest from
`.github/workflows/proof-digests.env` (single source of truth shared
with `.github/workflows/cryptol-proofs.yml`), so the local invocation
is byte-identical to the CI lane.

The slow local/offline Lagrange obligations are separate:

```bash
bash scripts/run-proofs.sh cryptol-offline
```

This runs `lagrange_recover_t2`, `lagrange_recover_t2_generic`,
`overdet_consistent_t2`, and `lagrange_recover_t3_vectors`. They are not
part of CI because the pinned Cryptol/Z3 image timed out on
`lagrange_recover_t2` at the 30-minute per-proof cap.

**Prerequisites.** A working Docker daemon (the wrapper fails fast with
exit code 3 if `docker info` does not succeed). No native Cryptol or
Z3 install is required; both ship inside the pinned container.

**Per-property output discipline.** Each `:prove` directive emits one
`Q.E.D.` line on success or a `Counterexample` block on failure. The
CI-safe wrapper greps for `^Counterexample` plus solver errors/timeouts,
then requires at least 26 `Q.E.D.` lines.

**Manual Docker invocation (advanced).** Reviewers who want to drive
Cryptol interactively (for ad-hoc property exploration outside the
locked directive list) can still invoke the pinned container directly:

```bash
# Pull the sha256-pinned Cryptol container.
docker pull "$(awk -F= '/^CRYPTOL_IMAGE=/ { print $2 }' .github/workflows/proof-digests.env)"

# Load + prove a CI-safe property (Cryptol 3.5.0).
docker run --rm \
  -v "$PWD:/work" -w /work \
  -e CRYPTOLPATH=/work \
  "$(awk -F= '/^CRYPTOL_IMAGE=/ { print $2 }' .github/workflows/proof-digests.env)" \
  -c ':set prover=z3' \
  -c ':set prover-timeout = 1800' \
  -c ':load spec/properties.cry' \
  -c ':prove mul_legacy_commutative'
```

The CI workflow at `.github/workflows/cryptol-proofs.yml` runs the
CI-safe directive list on every push, pull-request, and Sunday 06:00 UTC
cron (SD-R13-3). Every default `:prove` MUST return `Q.E.D.`.

## Native install (without Docker)

Cryptol ships pre-built binaries on the Galois GitHub release page:

```
https://github.com/GaloisInc/cryptol/releases
```

The locked Docker image pins **Cryptol 3.5.0** (released 2026-01-28).
A matching native install is available via the upstream tarball; the
release page lists per-platform downloads + their checksums. On macOS
the homebrew formula `brew install cryptol` tracks upstream stable.

System prerequisites for `:prove`: a working **Z3 4.8+** in `$PATH`.
Cryptol auto-detects Z3; manual configuration is only needed for
multi-backend setups (CVC4 / Boolector — future R14 work).

## Module layout

| File | Purpose | Cross-refs |
| ---- | ------- | ---------- |
| `gf256.cry` | GF(2^8) Russian-peasant `mul`, `xtimes`, `pow_254`-based `inv`, both polynomials (0x11D legacy, 0x11B AES). | `src/legacy.rs:36-49`, `src/legacy.rs:86-103`, `src/resplit.rs:18-22`, `src/resplit.rs:39-52` |
| `lagrange.cry` | Lagrange interpolation at `x=0` + at arbitrary `x` + over-determined consistency check; parameterised over the multiplier so it covers both polys; static threshold `t` constrained to `2..=3`. | `src/legacy.rs:133-175`, `src/legacy.rs:214-260` |
| `lagrange_t3_samples.cry` | Auto-generated 1024-row deterministic vector literal for the t=3 `:check`'d property. PRNG: SplitMix64 with seed `0x59EA4612CFD00A89`. | feeds `properties.cry::lagrange_recover_t3_vectors` |
| `properties.cry` | The property bundle. The default CI lane runs 26 GF/inversion `:prove` properties; the Lagrange t=2/t=3 properties are retained for `scripts/run-proofs.sh cryptol-offline`. | per-property comments in the file |

## Property index

The property names below are split between the CI-safe Cryptol lane and
the explicit local/offline Lagrange lane. Each carries a one-line
description + the Rust function it mirrors.

### CI-safe locked baseline — 17 × `:prove`

| # | Property | Claim | Rust twin |
| - | -------- | ----- | --------- |
| 1 | `mul_legacy_commutative` | a · b = b · a (legacy poly) | `src/legacy.rs::mul` |
| 2 | `mul_legacy_identity_one` | 1 is the multiplicative identity (legacy) | `src/legacy.rs::mul` + `src/legacy.rs::tests::mul_identity_one_is_neutral` |
| 3 | `mul_legacy_annihilator_zero` | 0 absorbs every input (legacy) | `src/legacy.rs::mul` + `src/legacy.rs::tests::mul_annihilator_zero_is_absorbing` |
| 4 | `mul_legacy_distributes_xor` | a · (b ⊕ c) = (a · b) ⊕ (a · c) (legacy) | `src/legacy.rs::mul` |
| 5 | `mul_aes_commutative` | a · b = b · a (AES poly) | `src/resplit.rs::mul_aes` |
| 6 | `mul_aes_identity_one` | 1 is the multiplicative identity (AES) | `src/resplit.rs::mul_aes` |
| 7 | `mul_aes_annihilator_zero` | 0 absorbs every input (AES) | `src/resplit.rs::mul_aes` |
| 8 | `mul_aes_distributes_xor` | a · (b ⊕ c) = (a · b) ⊕ (a · c) (AES) | `src/resplit.rs::eval_poly` (Horner relies on this) |
| 9 | `mul_aes_fips197_first_pair` | `mul_aes(0x57, 0x83) == 0xC1` (FIPS-197 §4.2 anchor) | `src/resplit.rs::tests` |
| 10 | `mul_aes_fips197_second_pair` | `mul_aes(0x57, 0x13) == 0xFE` (FIPS-197 §4.2 anchor) | `src/resplit.rs::tests` |
| 11 | `mul_legacy_pin_0x57_0x83` | `mul_legacy(0x57, 0x83) == 0x31` (legacy anchor) | `src/legacy.rs::tests` |
| 12 | `mul_legacy_pin_0x80_2` | `mul_legacy(0x80, 0x02) == 0x1D` (reduction anchor, legacy) | `src/legacy.rs::tests::ref_xtimes` |
| 13 | `cross_poly_distinguisher` | The two fields differ on at least one input | both `mul_*` together |
| 14 | `inv_legacy_round_trip` | `mul(a, inv(a)) == 1` for every a ≠ 0 (legacy) | `src/legacy.rs::inv` + `src/legacy.rs::tests` inverse-vs-reference |
| 15 | `inv_aes_round_trip` | `mul(a, inv(a)) == 1` for every a ≠ 0 (AES) | spec/gf256.cry `inv_aes` |
| 16 | `inv_legacy_involution` | `inv(inv(a)) == a` for every a ≠ 0 (legacy) | `src/legacy.rs::inv` |
| 17 | `inv_aes_involution` | `inv(inv(a)) == a` for every a ≠ 0 (AES) | spec/gf256.cry `inv_aes` |
### Local/offline Lagrange — 3 × `:prove` + 1 × `:check`

| # | Property | Claim | Rust twin |
| - | -------- | ----- | --------- |
| 18 | `lagrange_recover_t2` | t=2 recovery for c=1 polys is exact | `src/legacy.rs::interp_at_zero` |
| 19 | `lagrange_recover_t2_generic` | t=2 recovery for any c is exact | `src/legacy.rs::interp_at_zero` |
| 20 | `overdet_consistent_t2` | t=2-defined poly evaluated at an extra x yields the expected y | `src/legacy.rs::interp_at` + `src/main.rs` cross-check path |
| 21 | `lagrange_recover_t3_vectors` | t=3 recovery is exact across 1024 deterministic samples | `src/legacy.rs::interp_at_zero` |

Why `:check` instead of `:prove` for t=3: the universally-quantified
space is `256^6 ≈ 2.8×10^14`, which exceeds the container budget under
any realistic SMT bit-blasting. The honest form is to commit a
deterministic sample set + run Cryptol's `:check` over it. See R13-v2
M2 notes in `spec/properties.cry` for the full rationale.

### CI-safe user-emphasis extras — 9 × `:prove`

Per the user directive: **"for anything related to cryptography, and
constant-time cryptography make sure we have extensive test coverage
to prove what we do and that it works."** These extras go beyond the
locked baseline to maximise coverage of the algebraic kernel.

| # | Property | Claim | Rust twin / cryptographic role |
| - | -------- | ----- | ------------------------------ |
| 22 | `mul_aes_associative` | (a · b) · c = a · (b · c) (AES) | load-bearing for Horner's rule at `src/resplit.rs::eval_poly` |
| 23 | `mul_legacy_associative` | (a · b) · c = a · (b · c) (legacy) | load-bearing for the product Π in Lagrange recovery at `src/legacy.rs::interp_at_zero` |
| 24 | `mul_aes_fips197_self_square` | `mul_aes(1, 1) == 1` | identity-squared anchor; smoke-test pin against future refactors |
| 25 | `mul_aes_inv_pin_0x53_0xca` | `mul_aes(0x53, 0xCA) == 1` AND `inv_aes(0x53) == 0xCA` | canonical AES S-box inverse pair (used in AES SubBytes derivation) |
| 26 | `mul_aes_reduction_anchor` | `mul_aes(0x02, 0x80) == 0x1B` | explicit witness of the 0x11B reduction polynomial choice |
| 27 | `xtimes_aes_correct` | `mul_aes(a, 2) == xtimes_aes(a)` | confirms the doubling primitive matches the Russian peasant (AES) |
| 28 | `xtimes_legacy_correct` | `mul_legacy(a, 2) == xtimes_legacy(a)` | same as 27 for legacy poly; mirrors `src/legacy.rs::tests::ref_xtimes` |
| 29 | `zero_product_aes` | `mul_aes(a, b) == 0 ⇔ (a == 0 ∨ b == 0)` | confirms GF(2^8) has no zero divisors; load-bearing for Lagrange denominator nonzero-ness |
| 30 | `inv_aes_homomorphism` | `inv(a · b) == inv(a) · inv(b)` for a, b ≠ 0 (AES) | multiplicative-group homomorphism; characterises GF(2^8)\{0} structure |

**Default CI total: 26 `:prove` directives.** Offline Lagrange total:
3 `:prove` directives + 1 `:check` directive. The spec file still keeps
30 named properties/checks for review and manual verification.

## Expected solver wall-clock

| Property class | Properties | Per-property time | Notes |
| -------------- | ---------- | ----------------- | ----- |
| GF anchored constants (single inputs) | 9-13, 24-26 | < 1 s | Cryptol simplifies to constant |
| GF byte-pair properties | 1-8 | 1-5 s each | 65 536-pair sweep via bit-blast |
| GF inverse round-trips | 14-17 | 5-30 s | 8-iteration `pow_254` unfolds + 256 cases |
| Lagrange t=2 | 18-19 | offline only; can hit 30-min timeout | 256^4 = 4×10^9 input space + denominator inversion |
| Over-determined t=2 | 20 | offline only | similar to Lagrange t=2 |
| Triple-input properties (associativity) | 22, 23 | 5-30 min each | 256^3 = 16.7M; expensive under bit-blast |
| `xtimes` correctness | 27, 28 | 1-5 s | reduces to 256 cases |
| Zero-product | 29 | 5-30 s | reduces to byte-pair sweep |
| Homomorphism (triple input under inv) | 30 | 5-30 min | 256^2 + double pow_254 unfolds |
| `:check` t=3 over 1024 samples | 21 | offline only | concrete evaluation, not SMT |

Total default CI budget: **< 30 min** wall-clock. The workflow container
timeout is 30 min. The per-`:prove` `:set prover-timeout = 1800` safety
net caps any individual property at the full container budget so an
unexpected solver hang fails fast.

## Regenerating the t=3 sample set

The vector literal in `lagrange_t3_samples.cry` is auto-generated and
deterministic. To reproduce:

```python
SEED = 0x59EA4612CFD00A89

def splitmix64(state):
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return state, z ^ (z >> 31)

state = SEED
out = []
while len(out) < 1024:
    state, w = splitmix64(state)
    row = [(w >> (8*i)) & 0xFF for i in range(6)]
    secret, c1, c2, x1, x2, x3 = row
    if x1 and x2 and x3 and len({x1, x2, x3}) == 3:
        out.append(row)
# Emit as a Cryptol [1024][6][8] literal.
```

Any future rotation MUST keep the seed pinned, document the rotation
rationale in the file header, and update both `lagrange_t3_samples.cry`
+ this README in the same PR.

## Adding new properties

The project posture: **every algebraic identity in
`src/legacy.rs::tests` or `src/resplit.rs::tests` should EVENTUALLY
have a Cryptol twin.** Phase A's locked scope covers the load-bearing
subset; future R14+ rounds can extend coverage incrementally.

To add a property:

1. Edit `spec/properties.cry` — append a new `property <name> ...`
   block + a comment naming the Rust twin + the cryptographic claim
   the property underwrites.
2. Add a matching `:prove` (or `:check`) line to
   `.github/workflows/cryptol-proofs.yml`.
3. If the property requires a new helper function, add it to the
   matching file (`gf256.cry` for GF kernels; `lagrange.cry` for
   Lagrange primitives) — not in `properties.cry`.
4. Re-run the workflow locally to confirm the property is solver-
   tractable inside the container budget.

## Risks & residue

- **Cryptol solver scalability for triple-input properties.**
  Associativity (`mul_aes_associative`, `mul_legacy_associative`) and
  homomorphism (`inv_aes_homomorphism`) walk a 256³ = 16.7M input
  space; Z3 bit-blasting may take several minutes each. The per-
  property `:set prover-timeout = 1800` safety net caps each at 30 min.
  If a future Cryptol+Z3 upgrade slows these beyond the container
  budget, downgrade them to `:check` over a sampled corpus (mirroring
  the M2 t=3 pattern).
- **Native vs containerised Z3 version skew.** The pinned Docker image
  bundles a specific Z3. Native installs of Cryptol may pull a
  different Z3 from the host package manager. The proofs are
  algebraic identities that any complete SMT solver should discharge,
  but in practice solver-version skew can affect wall-clock and rarely
  may produce indeterminate results. The CI image is the authoritative
  pin; locally-failed proofs against a divergent Z3 should be
  reproduced inside the pinned container before being treated as
  regressions.
- **Solver backend choice.** The locked default is Z3 (bundled with
  the Cryptol Docker image). A future R14 round may multi-backend the
  proofs for defence-in-depth against SMT-engine soundness bugs
  (Z3 + CVC4 + Boolector).
