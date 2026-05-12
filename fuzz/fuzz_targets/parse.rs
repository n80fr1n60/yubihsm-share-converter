//! R12-Phase-D / item #6: parse-target libFuzzer harness.
//!
//! INVARIANT: `parse_legacy_share` MUST never panic — neither on a
//! well-formed share line NOR on an arbitrarily malformed byte sequence.
//! The contract is "always returns a Result"; this harness exercises
//! the contract against libFuzzer-generated input.
//!
//! Coverage target: the parse-time validation paths in
//! `src/parse.rs::parse_legacy_share` — splitn-on-`-` + `parse::<u8>()`
//! for threshold/index + `base64::decode` for the payload.
//!
//! Production callers always pass a `&str` (via `std::str::from_utf8`
//! on stdin). To exercise the parser against arbitrary bytes we use
//! `from_utf8_lossy`, which never errors and replaces invalid UTF-8
//! with U+FFFD. That keeps the harness focused on the parser's logic
//! rather than rejecting half the corpus on the UTF-8 boundary alone.

#![no_main]
use libfuzzer_sys::fuzz_target;
use yubihsm_share_converter::parse::parse_legacy_share;

fuzz_target!(|data: &[u8]| {
    // Assert: never panics, always returns a Result.
    let s = String::from_utf8_lossy(data);
    let _ = parse_legacy_share(&s);
});
