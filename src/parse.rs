//! Legacy share-line parser (`T-N-base64`) + `LegacyShare` struct.
//!
//! Extracted from `src/main.rs` in R12-Phase-D so the `fuzz/` crate can
//! import the parser via the lib (`yubihsm_share_converter::parse::*`).
//! Mirrors the R11-C3 pattern that pulled `legacy` + `resplit` + `secret`
//! into their own lib modules.
//!
//! Visibility is `pub` (rather than the previous module-internal form in
//! main.rs) for cross-crate use by the fuzz harnesses. The behaviour is
//! byte-identical to the pre-R12-Phase-D body — no input range changes,
//! no error-message wording changes.
//!
//! R4-4 invariant: the hand-rolled `Debug` impl on `LegacyShare` MUST
//! redact the secret-bearing `payload`. A future refactor that
//! `#[derive(Debug)]` would silently leak share bytes into any
//! `eprintln!("{:?}", share)` / `dbg!(share)` / panic backtrace.
//!
//! H5 invariant: the `Drop` impl zeroes the secret-bearing `payload`
//! buffer. Don't `#[derive(ZeroizeOnDrop)]` here — the non-secret
//! `threshold`/`index` integers must NOT be scrubbed (the latter is the
//! public Shamir x-coordinate; the former is the parsed `T` field).

use zeroize::Zeroize;

/// A single parsed legacy share line: `T-N-base64`.
///
/// `threshold` and `index` are non-secret metadata; `payload` is the
/// raw Y-byte sequence (one byte per byte of the recovered secret).
pub struct LegacyShare {
    pub threshold: u8,
    pub index: u8,        // 1-based, also the X coordinate in the legacy field
    pub payload: Vec<u8>, // raw Y-bytes, one per byte of the secret
}

// R4-4: hand-rolled Debug to keep secret payload bytes out of any
// future eprintln!("{:?}", share) / dbg!(share) / panic backtrace.
// The non-secret threshold + index are printed; payload is reduced
// to its byte length.
impl std::fmt::Debug for LegacyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyShare")
            .field("threshold", &self.threshold)
            .field("index", &self.index)
            .field(
                "payload",
                &format_args!("<redacted; {} bytes>", self.payload.len()),
            )
            .finish()
    }
}

// H5: zero the share payload on drop. We don't `#[derive(ZeroizeOnDrop)]`
// here because `u8` does not impl `Zeroize` directly in a derive context
// for non-Zeroize fields (`threshold`/`index` are non-secret integers we
// deliberately don't want to scrub). Hand-rolled Drop only touches the
// secret-bearing `payload`.
impl Drop for LegacyShare {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Parse a single share line of the form `T-N-base64`. Returns the
/// parsed `LegacyShare` or a redacted error message — see the R4-4
/// audit pass below for the redaction rationale.
///
/// Behaviour: byte-identical to the pre-R12-Phase-D body that lived in
/// `src/main.rs`. The error-message wording and accepted-range bounds
/// (threshold ∈ [2..=31], index ∈ [1..=255]) are part of the contract
/// — the parse-specific tests in `mod tests` below pin them.
pub fn parse_legacy_share(s: &str) -> Result<LegacyShare, String> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    let parts: Vec<&str> = s.trim().splitn(3, '-').collect();
    if parts.len() != 3 {
        return Err(format!(
            "expected `T-N-base64`; got line of length {} (content redacted)",
            s.len()
        ));
    }
    let threshold: u8 = parts[0].parse().map_err(|e| {
        format!(
            "bad threshold field (length {}, content redacted): {e}",
            parts[0].len()
        )
    })?;
    let index: u8 = parts[1].parse().map_err(|e| {
        format!(
            "bad index field (length {}, content redacted): {e}",
            parts[1].len()
        )
    })?;
    if !(2..=31).contains(&threshold) {
        return Err(format!("threshold {threshold} out of range (2..=31)"));
    }
    if !(1..=255).contains(&index) {
        return Err(format!("index {index} must be 1..=255"));
    }
    // R4-4 audit pass: the base64 crate's `DecodeError::Display` reports
    // the offending byte's value (e.g. "Invalid byte 33, offset 0."),
    // which on a malformed share line CAN be a payload byte. We classify
    // the error into a non-content category and report only the encoded
    // length plus the kind — never the byte value or its offset.
    let payload = STANDARD_NO_PAD.decode(parts[2].as_bytes()).map_err(|e| {
        let kind = match e {
            base64::DecodeError::InvalidByte(_, _) => "invalid base64 byte",
            base64::DecodeError::InvalidLength(_) => "invalid base64 length",
            base64::DecodeError::InvalidLastSymbol(_, _) => "invalid base64 last symbol",
            base64::DecodeError::InvalidPadding => "invalid base64 padding",
        };
        format!(
            "bad base64 payload (length {}, content redacted): {kind}",
            parts[2].len()
        )
    })?;
    Ok(LegacyShare {
        threshold,
        index,
        payload,
    })
}

// ───────────────────────────── tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_share_format() {
        // 70 base64 chars → 52 raw bytes (matches yubihsm-setup regex).
        let payload = vec![0x42u8; 52];
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &payload);
        assert_eq!(b64.len(), 70);
        let s = format!("2-1-{b64}");
        let parsed = parse_legacy_share(&s).unwrap();
        assert_eq!(parsed.threshold, 2);
        assert_eq!(parsed.index, 1);
        assert_eq!(parsed.payload, payload);
    }

    // M1: post-widening, threshold 10 (and up to 31) must parse cleanly.
    #[test]
    fn parse_threshold_10_accepted() {
        let payload = vec![0x42u8; 52];
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &payload);
        assert_eq!(b64.len(), 70);
        let s = format!("10-1-{b64}");
        let parsed = parse_legacy_share(&s).expect("threshold=10 must parse after M1");
        assert_eq!(parsed.threshold, 10);
        assert_eq!(parsed.index, 1);
    }

    // M1: thresholds above the 2..=31 window must still be rejected.
    #[test]
    fn parse_threshold_32_rejected() {
        let payload = vec![0x42u8; 52];
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &payload);
        let s = format!("32-1-{b64}");
        let err = parse_legacy_share(&s).expect_err("threshold=32 must be rejected");
        assert!(err.contains("32"), "unexpected error: {err}");
        assert!(err.contains("out of range"), "unexpected error: {err}");
    }

    // M1: post-widening, share-index 10 (and up to 255) must parse cleanly.
    #[test]
    fn parse_index_10_accepted() {
        let payload = vec![0x42u8; 52];
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &payload);
        assert_eq!(b64.len(), 70);
        let s = format!("3-10-{b64}");
        let parsed = parse_legacy_share(&s).expect("index=10 must parse after M1");
        assert_eq!(parsed.threshold, 3);
        assert_eq!(parsed.index, 10);
    }

    // M1: index = 0 is still rejected (1..=255 is the new range).
    #[test]
    fn parse_index_0_rejected() {
        let payload = vec![0x42u8; 52];
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &payload);
        let s = format!("3-0-{b64}");
        let err = parse_legacy_share(&s).expect_err("index=0 must be rejected");
        assert!(err.contains("index 0"), "unexpected error: {err}");
        assert!(err.contains("1..=255"), "unexpected error: {err}");
    }

    // R4-4: the hand-rolled `Debug` impl on `LegacyShare` must redact the
    // payload bytes. We construct a recognisable canary payload (ASCII
    // "ABCD" = 0x41 0x42 0x43 0x44) and assert the formatted string
    // reports only the byte length, NOT any of the byte values in any
    // common debug encoding (decimal, hex, ASCII).
    #[test]
    fn legacy_share_debug_redacts_payload() {
        let share = LegacyShare {
            threshold: 2,
            index: 1,
            payload: vec![0x41, 0x42, 0x43, 0x44],
        };
        let dbg = format!("{share:?}");
        assert!(
            dbg.contains("<redacted; 4 bytes>"),
            "Debug must contain the redaction marker; got: {dbg}"
        );
        // Non-secret metadata is allowed and useful for diagnosis.
        assert!(
            dbg.contains("threshold: 2"),
            "Debug should still print threshold; got: {dbg}"
        );
        assert!(
            dbg.contains("index: 1"),
            "Debug should still print index; got: {dbg}"
        );
        // Forbidden: the ASCII rendering of the canary payload.
        assert!(!dbg.contains("ABCD"), "Debug leaked ASCII payload: {dbg}");
        // Forbidden: hex byte renderings (lowercase + uppercase).
        for h in ["41", "42", "43", "44"] {
            assert!(!dbg.contains(h), "Debug leaked hex byte {h}: {dbg}");
        }
        // Forbidden: the decimal `[u8]`-debug rendering.
        for d in ["65", "66", "67", "68"] {
            assert!(!dbg.contains(d), "Debug leaked decimal byte {d}: {dbg}");
        }
        // Forbidden: the literal `Vec<u8>` debug bracket form.
        assert!(
            !dbg.contains("[65, 66, 67, 68]"),
            "Debug leaked Vec<u8> array form: {dbg}"
        );
    }
}
