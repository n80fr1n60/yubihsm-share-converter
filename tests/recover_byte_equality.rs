// tests/recover_byte_equality.rs — R13-v2 M4 byte-equality regression
// guard. Runs the post-R13 `yubihsm_share_converter::recover::recover`
// against every input under `fuzz/corpus_seed/recover/` + asserts the
// output blob is byte-identical to the committed golden fixture
// `tests/fixtures/recover-golden/<seed-basename>.expected.bin`.
//
// The golden fixtures are generated ONCE at pre-R13-C HEAD via the
// `examples/golden_gen.rs` one-off driver + committed alongside the
// lib-move commit. Subsequent regressions of any kind (a careless
// refactor of `legacy::interp_at_zero`, an arithmetic bug introduced
// during a future round) are detected by `cargo test recover_byte_equality`.
//
// R13-v1 → R13-v2 sequencing note: the goldens are bytes-from-pre-R13
// `recover_for_fuzz` (deleted in this commit). The post-move
// `recover()` MUST produce byte-identical bytes; this test is the
// load-bearing proof of the "pure refactor" claim in FIX_PLAN.html
// anchor #r13-03.

use std::path::PathBuf;
use yubihsm_share_converter::parse::{parse_legacy_share, LegacyShare};
use yubihsm_share_converter::recover::recover;

#[test]
fn recover_byte_equality_against_committed_golden_fixtures() {
    let seed_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus_seed")
        .join("recover");
    let golden_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("recover-golden");

    assert!(
        seed_dir.is_dir(),
        "seed corpus missing: {}",
        seed_dir.display()
    );
    assert!(
        golden_dir.is_dir(),
        "golden fixtures missing: {}",
        golden_dir.display()
    );

    let mut checked = 0_usize;
    for entry in std::fs::read_dir(&seed_dir).expect("read seed dir") {
        let seed_path = entry.expect("dirent").path();
        if !seed_path.is_file() {
            continue;
        }
        let basename = seed_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let golden_path = golden_dir.join(format!("{}.expected.bin", basename));

        let seed_bytes = std::fs::read(&seed_path).expect("read seed");
        // Replicate the production recover() input shape via the same
        // parsing pipeline the binary uses on stdin:
        let (shares, payload_len) = match parse_seed_input(&seed_bytes) {
            Some(p) => p,
            None => continue, // malformed input — match production fail-soft
        };

        let actual = recover(&shares, payload_len).expect("recover ok");
        let expected = std::fs::read(&golden_path).unwrap_or_else(|_| {
            panic!(
                "missing golden fixture for {}: expected at {}",
                basename,
                golden_path.display()
            )
        });
        assert_eq!(
            actual, expected,
            "byte-equality regression on seed {}",
            basename
        );
        checked += 1;
    }
    assert!(
        checked >= 2,
        "expected ≥ 2 seed inputs (SD-R12-v3-2 corpus); got {}",
        checked
    );
}

/// Mirrors the parsing shape that `fuzz/fuzz_targets/recover.rs` uses on
/// its `data: &[u8]`. Same `parse_legacy_share` line-by-line walk, same
/// payload_len agreement check, same `shares.len() >= 2` filter. Returns
/// `None` on any malformed input — match production fail-soft posture.
fn parse_seed_input(bytes: &[u8]) -> Option<(Vec<LegacyShare>, usize)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut shares = Vec::new();
    let mut len: Option<usize> = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let s = parse_legacy_share(line).ok()?;
        if let Some(l) = len {
            if l != s.payload.len() {
                return None;
            }
        } else {
            len = Some(s.payload.len());
        }
        shares.push(s);
    }
    let payload_len = len?;
    if shares.len() < 2 {
        return None;
    }
    if !(36..=60).contains(&payload_len) {
        return None;
    }
    Some((shares, payload_len))
}
