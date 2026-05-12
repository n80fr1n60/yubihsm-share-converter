# Crypto Spec — yubihsm-share-converter

This document specifies the cryptographic primitives, parameters, and wire
formats the converter implements. Every claim has a load-bearing site in
the codebase; the `file:line` anchors point at the current production text.

## 1. Field arithmetic

Both halves of the converter operate over `GF(2^8)` (the 256-element
binary extension field). The two halves use **different** reduction
polynomials and the share material does NOT round-trip through a
single-field implementation:

- **Legacy share format** — `GF(2^8) / 0x11D`. Polynomial
  `x^8 + x^4 + x^3 + x^2 + 1`; low byte `0x1D`. This is the field used by
  `rusty-secrets 0.0.2`, the library `yubihsm-setup ksp` shells out to
  for the legacy wrap-key share emission. The converter reads these
  shares byte-for-byte; the reduction constant is wired in at
  `src/legacy.rs:49-62` (the branchless Russian-peasant `mul`) and at
  the `mul`/`inv` table-build path.

- **Resplit (manager) format** — `GF(2^8) / 0x11B`. Polynomial
  `x^8 + x^4 + x^3 + x + 1`; low byte `0x1B`. This is the AES /
  Rijndael field per **FIPS-197 §4.2.1**. `yubihsm-manager` accepts
  shares emitted in this field; the converter hand-rolls a Shamir split
  in this field at `src/resplit.rs` (mul_aes, eval_poly, split). The
  R9-H3 hand-roll deliberately avoids the `vsss-rs` 5.x dependency
  because that library leaked share bytes through allocator slots
  outside our zeroize control (`Cargo.toml:24-27`).

Both `mul` functions use the R11-C2 branchless Russian-peasant shape — a
fixed 8-iteration loop with a mask-based reduction step. There is no
data-dependent branch on the operand, so the multiplications are
constant-time independent of operand value. The legacy field's `inv` is
implemented as `a^254` via a fixed 254-iteration repeated-mul chain
(R12-04); also branchless and operand-independent in timing.

The two-field separation matters: an implementation that hard-codes only
poly `0x11B` (e.g. naively reused AES Galois multiplication) will
silently mis-decode legacy shares. The cross-poly anchors in §6 below
detect any such confusion.

## 2. Shamir secret sharing parameters

### Legacy (recover-side)

- **Threshold `t`** ∈ `[2..=31]`. Enforced at parse time at
  `src/main.rs:345` (`if !(2..=31).contains(&threshold)`). The upper
  bound `31` matches `rusty-secrets 0.0.2`'s historical cap.
- **Share count `n`** ∈ `[t..=255]`. Bounded by the share index space
  (one byte) and by `parse_legacy_share` at `src/main.rs:348-350`.
- **Share index `x`** ∈ `[1..=255]`. Index 0 is the secret slot and is
  rejected at recovery time (`src/legacy.rs:111-114`).

### Resplit (manager-side)

- **Threshold `t`** ∈ `[2..=9]`. Bounded by the manager's wire-format
  regex (single hex digit for the threshold field).
- **Share count `n`** ∈ `[t..=9]`. Same regex cap; enforced before
  resplit at `src/main.rs:889` (`if n > 9 { return ExitCode::from(9); }`).
- **Share index `x`** ∈ `[1..=9]`. Enforced after split at
  `src/main.rs:940-942` (refuse to emit any share whose first byte falls
  outside `[1..=9]`).

The manager-side window is strictly smaller than the legacy-side window;
a 12-of-12 legacy share set CANNOT round-trip through the resplit path
because the manager regex cannot represent `n > 9`. The converter refuses
this combination loudly rather than silently truncating.

## 3. Share encoding

### Legacy share line format

```
T-N-base64(payload)
```

- `T` — decimal threshold, `[2..=31]`.
- `N` — decimal share index, `[1..=255]`.
- `payload` — `STANDARD_NO_PAD` base64 of the wrap-blob (§5). A 52-byte
  blob (AES-256 wrap) encodes to a 70-character base64 string; legitimate
  legacy share lines are therefore 74-78 characters long.
- Separator: single ASCII `-`. The base64 alphabet does not contain `-`,
  so `splitn(3, '-')` is unambiguous (`src/main.rs:326`).
- Parse site: `parse_legacy_share` at `src/main.rs:323-373`. Error
  messages redact the offending byte value (`InvalidByte`/`InvalidLength`
  classified into a non-content category at `src/main.rs:356-367`).

### Manager (resplit) share line format

```
T-X-hex(payload)
```

- `T` — decimal threshold, single digit `[2..=9]`.
- `X` — decimal share index, single digit `[1..=9]`.
- `payload` — lowercase hex of the wrap-blob (§5). A 52-byte blob
  encodes to a 104-character hex string.
- Separator: single ASCII `-`. The hex alphabet `[0-9a-f]` does not
  contain `-`, so the parser is unambiguous.

The two formats are distinguishable on the wire: the legacy form embeds
`+`/`/` characters from the base64 alphabet, the manager form is
`[0-9a-f]`-only. A converter that gets a manager-format share line in
its recover input will fail the base64 decode loudly.

## 4. Recovery semantics

### Per-byte Lagrange interpolation at `x = 0`

Recovery treats each byte position of the wrap-blob independently:

```
L(0) = Σ_i  y_i · Π_{j≠i}  x_j / (x_i ⊕ x_j)
```

In characteristic 2, subtraction equals XOR, so `-x_j == x_j`. The site
is `legacy::interp_at_zero` at `src/legacy.rs:99-141`. The function takes
a closure that re-creates the `(x_i, y_i)` iterator twice — once for the
phase-1 validation pass (reject `x = 0` shares, reject duplicate
`x`-coordinates), once for the phase-3 Lagrange evaluation. The closure
shape is borrowck-friendly and avoids materialising a per-byte
`Vec<(u8, u8)>` of secret-bearing share bytes on the heap.

### Disjoint-subset cross-check (`n ≥ 2t`)

When the operator supplies at least `2t` shares, recovery runs **twice**
against disjoint subsets `shares[..t]` and `shares[t..2t]`, then
`constant_time_eq`s the two recovered blobs (`src/main.rs:798`). A
single corrupt share appears in at most one of the two subsets, so the
disjoint cross-check catches any one-share corruption. The recovered
blobs are wrapped in `Zeroizing<Vec<u8>>` (`src/main.rs:770, :786`) and
the comparison is constant-time so the comparison itself doesn't leak a
divergent-byte oracle.

### Over-determined byte-wise verification (`t < n < 2t`)

When the operator supplies more than `t` but fewer than `2t` shares, the
disjoint-subset cross-check is impossible. Instead, the converter
predicts each extra share's `y_i` byte-by-byte via `legacy::interp_at`
(the polynomial is uniquely determined by `shares[..t]`) and compares
against the actual share payload (`src/main.rs:805-841`). The R12-05
hardening turned the per-byte early-return into a full-blob
constant-time comparison; the diagnostic message names the failing
share-index but NOT the failing byte-index (denying the partial-corruption
oracle described in `THREAT-MODEL.md` §2 item 5).

### Two-of-two recovery (`n == t`)

When `n == t`, no extra share exists; recovery cannot detect a corrupt
share. The converter warns the operator at `src/main.rs:851-853` and
proceeds (the operator has no other option). The runbook recommends
`n ≥ t + 1` for any ceremony that needs end-to-end share-integrity
assurance.

## 5. Wrap-blob layout

The wrap-blob — the secret recovered from the legacy shares, and the
input to the resplit Shamir split — has a fixed binary layout:

```
+--------+--------+----------------+----------------+---------+
| wrap_id | domain | capabilities  | delegated_caps | aes_key |
|  (2 BE) | (2 BE) | (8 BE)        | (8 BE)         | (K B)   |
+--------+--------+----------------+----------------+---------+
   2 B      2 B         8 B              8 B           K B
```

Total length: `20 + K` bytes, where `K ∈ {16, 24, 32}` for AES-128 /
AES-192 / AES-256 wrap keys respectively. Concrete blob sizes:

| AES variant | K  | Total blob length |
| ----------- | -- | ----------------- |
| AES-128     | 16 | 36 B              |
| AES-192     | 24 | 44 B              |
| AES-256     | 32 | 52 B              |

The constant cap `MAX_PAYLOAD_LEN = 60` at `src/main.rs:388` is the
hardcoded upper bound on per-share payload length: 20 B header + 32 B
key + 8 B reserved headroom for any future format extension. Any
payload outside `[MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN]` is rejected at
`src/main.rs:443-446`.

All multi-byte fields are big-endian. The byte order matches the wire
shape that `yubihsm-setup ksp` emits and that `yubihsm-shell put-wrapped`
consumes, so the converter is byte-transparent on this layer.

## 6. FIPS-197 anchors

The reduction polynomials are pinned by **cross-poly distinguisher
tests** — products that have different values under the two polynomials,
so the test fails loud if the wrong constant were wired in:

### AES poly `0x11B`

- `resplit::mul_aes(0x57, 0x83) == 0xC1` — pinned in
  `resplit::tests::mul_aes_aes_poly_0x57_0x83_yields_0xc1` at
  `src/main.rs:1318-1321` (test scaffolding for the resplit module).
  This is the canonical FIPS-197 §4.2.1 worked example.
- `resplit::mul_aes(0x57, 0x13) == 0xFE` — pinned in
  `resplit::tests::mul_aes_aes_poly_0x57_0x13_yields_0xfe` at
  `src/main.rs:1326-1331`. The second pair pins the polynomial uniquely
  (two independent products determine the reduction constant).

### Legacy poly `0x11D`

- `legacy::mul(t, 0x57, 0x83) == 0x31` — pinned at `src/legacy.rs:400`.
  Note this is **different** from the AES-poly answer `0xC1`; under poly
  `0x11D` the product is `0x31`. This anchor would fail loud if the
  legacy module accidentally reduced by `0x1B` instead of `0x1D`.
- `legacy::mul(t, 0x80, 2) == 0x1D` — pinned at `src/legacy.rs:411`.
  `0x80 · 2` reduces by the polynomial low byte; under `0x11D` the
  answer is `0x1D`, under `0x11B` it would be `0x1B`. A direct probe of
  the reduction constant.

## 7. Out-of-scope cryptographic concerns

The following are NOT covered by this spec; see `THREAT-MODEL.md` §3 for
the full list. Crypto-relevant out-of-scope items:

- **SLSA build provenance** and **binary signing** — per maintainer
  directive, not in scope for this project.
- **Quantum-resistance.** Shamir secret sharing is information-theoretic
  and therefore not affected by quantum cryptanalysis at the primitive
  level. The wrap-key stored inside the blob is AES; quantum resistance
  for the AES wrap is a YubiHSM-firmware-domain concern, not a converter
  concern.
- **Side-channel resistance against physical adversaries** — the
  branchless GF arithmetic defends against cache-timing within a process
  boundary; physical EM/power-trace attacks against the host CPU are
  out of scope.
