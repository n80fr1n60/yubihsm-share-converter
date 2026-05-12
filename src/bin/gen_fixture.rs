// Deterministic toy-share fixture generator for tests/cli.rs (H3, M-C3).
//
// Emits a 2-of-3 legacy share set (rusty-secrets 0.0.2 wire format
// `T-N-base64`, GF(2^8) reduction polynomial 0x11D) over a fabricated
// wrap-blob:
//
//   wrap_id (2 BE) | domains (2) | caps (8) | delegated (8) | aes_key (K)
//
// where K ∈ {16, 24, 32} for AES-128 / AES-192 / AES-256, giving total
// blob lengths of 36, 44, 52 bytes respectively. The blob bytes are a
// known pattern (`(i*7)^0xA5`) so the fixture is recognisable when read
// in isolation. The polynomial coefficients come from
// `StdRng::seed_from_u64(seed)` with a key-length-specific seed so each
// AES variant produces deterministic, distinct fixtures that are
// bit-stable across runs and Rust toolchain versions.
//
// USAGE — regenerate from a clean checkout:
//
//   cargo run --release --bin gen_fixture                     > tests/data/toy_2of3.txt
//   cargo run --release --bin gen_fixture -- --key-len=16     > tests/data/toy_2of3_aes128.txt
//   cargo run --release --bin gen_fixture -- --key-len=24     > tests/data/toy_2of3_aes192.txt
//   cargo run --release --bin gen_fixture -- --key-len=32     > tests/data/toy_2of3.txt
//
// (No-arg invocation is identical to `--key-len=32`; both forms preserve
// the original AES-256 fixture byte-for-byte for backward compatibility.)
//
// SEED CONTRACT (do not change without regenerating all three fixtures):
//   key_len = 16  →  seed 0xC0FFEE_AE5128  →  toy_2of3_aes128.txt
//   key_len = 24  →  seed 0xC0FFEE_AE5192  →  toy_2of3_aes192.txt
//   key_len = 32  →  seed 0xC0FFEE         →  toy_2of3.txt        (legacy)
//
// The fixture files are committed to the repo. Re-run this generator
// only if the blob layout or seed contract changes.
//
// IMPORTANT: this is *not* a real wrap-key. It is deliberately
// recognisable to avoid being mistaken for one. All fixtures under
// `tests/data/` are deterministic outputs of this binary; no key bytes
// in this repo have ever existed on a real HSM.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use rand::{rngs::StdRng, Rng, SeedableRng};

// R11-C3 R10-M2: drop the inline replica of legacy::* and import the
// canonical implementations from `yubihsm_share_converter::legacy`
// instead. The R11/C3 module split made `legacy` `pub`, so this bin no
// longer needs a fork-and-trim copy. `legacy::mul` is the constant-time
// branchless Russian-peasant introduced in R11/C2; the previous inline
// version was the table-walk form. Both produce identical outputs over
// the same field (GF(2^8) / 0x11D), so the regenerated fixtures are
// byte-identical to the committed ones — exhaustively verified by
// `legacy::tests::mul_branchless_matches_reference_exhaustive`.
//
// R12-C-04: the `Tables` struct + `build_tables` constructor were
// dropped from production code. `legacy::mul` now takes (a, b) directly
// — no &Tables arg, no precomputed log/exp tables. The output bytes
// over poly 0x11D are unchanged; this fixture generator's output
// remains byte-identical to the committed `tests/data/toy_2of3*.txt`.
use yubihsm_share_converter::legacy::mul;

fn main() {
    // M-C3: parameterise on AES key length. Default (no arg) keeps the
    // historic AES-256 fixture byte-for-byte stable. Any other arg form
    // panics with a clear message — there is intentionally no
    // partial-match / abbreviation support here, since this tool runs
    // only from the repo's regeneration commands.
    let key_len: usize = match std::env::args().nth(1).as_deref() {
        Some("--key-len=16") => 16,
        Some("--key-len=24") => 24,
        Some("--key-len=32") | None => 32,
        other => panic!("unknown arg {other:?}; use --key-len=16|24|32"),
    };
    let payload_len = 20 + key_len; // 36, 44, or 52
    let seed: u64 = match key_len {
        16 => 0xC0FFEE_AE5128,
        24 => 0xC0FFEE_AE5192,
        32 => 0xC0FFEE,
        _ => unreachable!(),
    };

    // The "secret" is a fabricated wrap-blob. Pattern is recognisable:
    // byte i = (i*7)^0xA5 for i in 0..payload_len. Test code matches
    // on these explicit constants — see tests/cli.rs and the unit tests
    // in src/main.rs.
    let secret: Vec<u8> = (0..payload_len as u8)
        .map(|i| i.wrapping_mul(7) ^ 0xA5)
        .collect();
    assert_eq!(secret.len(), payload_len);

    // 2-of-3: degree-1 polys → 1 random coefficient per byte.
    let threshold: u8 = 2;
    let n: u8 = 3;
    let mut rng = StdRng::seed_from_u64(seed);

    // shares[i] = (x_i, y-bytes-vec)
    let mut shares: Vec<(u8, Vec<u8>)> = (1..=n).map(|x| (x, vec![0u8; secret.len()])).collect();

    for (byte_idx, &s) in secret.iter().enumerate() {
        let c1: u8 = rng.r#gen();
        let poly = [s, c1];
        for (x, share) in &mut shares {
            // f(x) = c0 + c1*x in GF(2^8)/0x11D
            // R12-C-04: mul is now (a, b) → u8, no &Tables arg.
            let mut acc: u8 = 0;
            let mut fac: u8 = 1;
            for &coeff in &poly {
                acc ^= mul(fac, coeff);
                fac = mul(fac, *x);
            }
            share[byte_idx] = acc;
        }
    }

    // Emit `T-N-base64` lines on stdout. The base64 length is a function
    // of payload_len: 36→48, 44→60, 52→70 unpadded chars.
    let expected_b64_len = match payload_len {
        36 => 48,
        44 => 60,
        52 => 70,
        _ => unreachable!(),
    };
    for (x, payload) in &shares {
        let b64 = STANDARD_NO_PAD.encode(payload);
        debug_assert_eq!(
            b64.len(),
            expected_b64_len,
            "{}-byte payload should encode to {} unpadded chars",
            payload_len,
            expected_b64_len
        );
        println!("{threshold}-{x}-{b64}");
    }
}
