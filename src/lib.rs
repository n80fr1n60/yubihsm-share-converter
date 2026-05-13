//! yubihsm-share-converter library: `legacy` + `parse` + `recover` +
//! `resplit` + `secret` modules exposed for cross-bin and cross-crate
//! reuse.
//!
//! Split out of `main.rs` in R11/C3 so the `gen_fixture` bin can drop
//! its inline duplicate of the legacy field tables and cross-import
//! `yubihsm_share_converter::legacy` directly (the dedupe lands in
//! R11/C3 commit 3; this commit is the structural prerequisite).
//!
//! R12-Phase-D: `parse` was carved out of `src/main.rs` so the
//! `fuzz/` crate (libFuzzer harnesses for parse/recover/resplit) can
//! import `parse_legacy_share` + `LegacyShare` via this lib. The
//! `recover_for_fuzz` seam exposed the math kernel of the production
//! `recover()` function for the recover-target fuzz harness — see
//! R13-C amendment below for the structural fix that supersedes it.
//!
//! R13-C / item 3: production `recover()` was MOVED from `main.rs`
//! to `src/recover.rs` as a pub lib item. The pre-R13 `recover_for_fuzz`
//! wrapper that lived in this file is DELETED; the fuzz harness now
//! imports the production function directly. The SD-R12-v3-1 follow-up
//! is structurally resolved.

pub mod legacy;
pub mod parse;
pub mod recover;
pub mod resplit;
pub mod secret;

// R13-C / item 3: `recover_for_fuzz` deleted. The fuzz harness now
// uses `yubihsm_share_converter::recover::recover` directly. See
// R12-v3 residue table SD-R12-v3-1 for the lock that scheduled this.
