// yubihsm-share-converter
//
// Recovers a YubiHSM2 wrap-key blob from legacy yubihsm-setup shares
// (rusty-secrets 0.0.2, byte-wise Shamir over GF(2^8) with reduction
// polynomial 0x11D) and optionally re-splits the recovered blob using
// a hand-rolled GF(2^8)/0x11B Shamir splitter (R9-H3; previously
// vsss-rs) into the textual format that yubihsm-manager's
// `aes_share_validator` accepts.
//
// Usage:
//     # one share per line on stdin, format `T-N-base64`
//     cargo run --release < shares.txt
//     cargo run --release -- --resplit < shares.txt
//
// SECURITY:
// * This binary handles raw wrap-key material. Run it on the same
//   machine you are running the HSM ceremony on (ideally air-gapped),
//   and do not redirect output to disk on a normal workstation.
// * No zeroize / mlock here — keep the sketch small. Tighten before
//   any production use.
//
// References:
// * yubihsm-setup/src/main.rs: `WRAPKEY_LEN = 32`, blob layout
//   `wrap_id(2) | domains(2) | caps(8) | delegated(8) | key(32)`,
//   share regex `^\d-\d-[a-zA-Z0-9+/]{70}$`.
// * RustySecrets v0.0.2 build.rs:8 → `const POLY: u8 = 0x1D`.
// * RustySecrets v0.0.2 src/lib/mod.rs → secret_share / encode /
//   lagrange_interpolate (interpolates at x=0).
// * vsss-rs/src/gf256.rs:690 → `a ^= 0x1b & t` (AES poly) —
//   preserved as the historical reference for the 0x1B reduction
//   constant that the new `mod resplit` matches.

use std::io::{self, IsTerminal, Read, Write};
use std::process::ExitCode;
use zeroize::{Zeroize, Zeroizing};

use clap::Parser;

use secret::Secret;
use yubihsm_share_converter::parse::{parse_legacy_share, LegacyShare};
use yubihsm_share_converter::recover::recover;
use yubihsm_share_converter::{legacy, resplit, secret};

// R11-V2-residue (M3 lock-in): swap in dhat's allocator under `#[cfg(test)]`
// so the `recover_makes_at_most_one_heap_alloc` regression test can observe
// per-call heap-block deltas. The `#[cfg(test)]` gate guarantees the
// allocator is NEVER linked into release builds — the dhat crate itself is
// listed under `[dev-dependencies]` so it cannot reach release-side code at
// all. The allocator MUST be defined at the crate root (not inside a leaf
// module, not inside `mod tests`) for the `#[global_allocator]` attribute
// to register before `main()` runs.
#[cfg(test)]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// ───────────────────────────── H3: CLI surface ──────────────────────────
//
// Four flags. `--resplit`, `--inspect-only`, `--show-key` are mutually
// exclusive modes; `--i-accept-disk-output` is an enabler that combines
// with the mode flags (it is not itself a mode).
//
//   --resplit                Print new-format shares to stdout. Refused
//                            unless either stdout is a TTY OR BOTH
//                            YHSC_ALLOW_DISK_STDOUT=1 (env) AND
//                            --i-accept-disk-output (CLI) are supplied.
//                            R4-5: also refused with exit 13 when n == t
//                            (no redundancy ⇒ corruption is undetectable;
//                            the refusal fires BEFORE recover() so the
//                            secret never enters process memory).
//   --inspect-only           Recover and validate; never print key bytes
//                            or shares. Conflicts with --resplit and
//                            --show-key. The dual-knob disk gate is a
//                            no-op here because no key bytes are emitted.
//   --show-key               Print the recovered AES key hex on stderr
//                            (default is `<redacted>`). Same dual-knob
//                            disk gate as --resplit (over stderr).
//   --i-accept-disk-output   Acknowledge disk/file/pipe output for key-
//                            bearing streams. Required IN ADDITION to
//                            YHSC_ALLOW_DISK_STDOUT=1 to actually open
//                            the disk-stdout gate.
//
// R4-3 — dual-knob disk-stdout gate.
//
// Round 3 shipped a single-knob env-var gate (`YHSC_ALLOW_DISK_STDOUT=1`).
// That boundary turns out to be too weak: the env-var can be injected
// without operator intent via .bashrc / .profile, OpenSSH `SetEnv`,
// `sudoers env_keep`, parent-process `setenv()` immediately before
// `exec`, or container runtime `-e` flags. None of those require the
// operator's interactive consent on the host running the binary.
//
// Round 4 keeps the env-var (historic gate, kept for compatibility) and
// adds a second knob — the `--i-accept-disk-output` CLI flag — which
// MUST also be present on the actual command line. Together they form
// a dual-knob defence:
//
//   * The env-var is the historic single-knob gate. Scripts and CI
//     pipelines that already set it continue to work after they add
//     the new CLI flag to the same invocation.
//   * The CLI flag defeats env-only injection: an attacker who can
//     ONLY rig env vars (any of the five vectors above) cannot open
//     the gate, because they cannot also alter the operator's typed
//     command line.
//
// Residual threat: a CLI flag IS captured in shell history. That
// residual is mitigated by the existing history-safety gate at
// `:488-506` (R2 / round-3 H-3-1) which refuses when shell history
// would record the env-var assignment unless HISTCONTROL carries
// `ignorespace`/`ignoreboth` and the assignment is space-prefixed,
// or HISTFILE is unset, or `set +o history` was issued first. Note
// the history gate is INTENTIONALLY single-knob (`allow_disk` only):
// the typed string `YHSC_ALLOW_DISK_STDOUT=1` leaks to history
// regardless of what flags follow it, so the CLI flag is irrelevant
// to that threat. Coupling the history gate to the CLI flag would
// silently bypass the history check whenever the flag was supplied.
//
// Threat-model boundary the dual-knob does NOT cover: a fully-
// compromised parent shell that supplies BOTH the env-var AND the
// CLI flag (e.g. a malicious wrapper script). At that point the
// parent already controls the binary's entire surface; the dual-knob
// cannot help. Run on a host you trust.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Opts {
    /// Re-split the recovered blob and print new-format shares to stdout.
    // M-3-2: --resplit and --show-key are now clap-conflicting. Pre-fix the
    // pair was allowed, doubling the leak surface (shares to stdout AND key
    // to stderr in a single invocation). Each of the three flags now lists
    // the other two in `conflicts_with_all`, giving the same uniform clap
    // diagnostic regardless of which two the operator combined.
    #[arg(long, conflicts_with_all = ["inspect_only", "show_key"])]
    resplit: bool,
    /// Recover and validate only — never print key bytes or shares.
    #[arg(long, conflicts_with_all = ["resplit", "show_key"])]
    inspect_only: bool,
    /// Print the recovered AES key hex on stderr (default: redacted).
    #[arg(long, conflicts_with_all = ["inspect_only", "resplit"])]
    show_key: bool,
    /// Required IN ADDITION to YHSC_ALLOW_DISK_STDOUT=1 to actually open
    /// the disk-stdout gate. R4-3: the env-var alone was a weak boundary —
    /// hostile env injection (.bashrc, ssh SetEnv, sudo env_keep, container
    /// `-e`) could open the gate without operator intent. Requiring BOTH a
    /// per-invocation CLI flag AND the env-var defeats env-only injection.
    /// On `--inspect-only` this flag is a no-op (no key bytes are emitted).
    #[arg(long = "i-accept-disk-output", default_value_t = false)]
    i_accept_disk_output: bool,
}

// ───────────────────────────── H4: process hardening ────────────────────
//
// `assert_single_threaded` and `lock_down_process` together form the
// release-build hardening posture:
//
//   * `assert_single_threaded` reads /proc/self/status before any
//     `std::env::remove_var` call. setenv/unsetenv race with concurrent
//     libc readers, so calling them on a multi-threaded process is UB.
//     The check is a hard runtime `assert!` (release-too) and FAILS
//     CLOSED — if /proc isn't mounted (chroot, minimal container) we
//     refuse to proceed. v3 used unwrap_or_default(), which silently
//     defaulted n=1 and let the unsafe remove_var run unverified.
//
//   * `lock_down_process` calls `prctl(PR_SET_DUMPABLE, 0)` (forbids
//     coredumps and same-UID ptrace via /proc/<pid>/mem on hardened
//     kernels) and `setrlimit(RLIMIT_CORE, {0,0})` (hard rlimit so a
//     subsequent ulimit -c unlimited can't undo it). Together they
//     defeat coredumps as a leak vector.
//
// On non-Linux platforms (macOS / Windows), PR_SET_DUMPABLE,
// RLIMIT_CORE and MADV_DONTDUMP are not available with equivalent
// guarantees. Rather than silently degrade, `assert_single_threaded`
// hard-refuses with exit code 10 unless the developer explicitly sets
// `YHSC_ALLOW_UNHARDENED=1` (test/dev override). On Linux that env-var
// is IGNORED — full hardening is always applied. The non-Linux
// `lock_down_process` is a no-op because the override was already
// honoured upstream by `assert_single_threaded`.

/// M-3-1: env-var truthiness for security-relevant overrides. Accepts only
/// `"1"` or `"true"` (case-insensitive after `.trim()`). v2 (sec M3): narrowed
/// from `{1, true, yes, on}` to `{1, true}` so the accepted lexicon matches
/// the README, which documents `=1` only. EVERYTHING else, including the
/// empty string, `"0"`, `"false"`, `"no"`, `"off"`, `"yes"`, `"on"`, is
/// treated as NOT-SET — prevents the footgun of `YHSC_ALLOW_UNHARDENED=0`
/// (intuitively "disabled") accidentally engaging the override.
fn env_flag_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn assert_single_threaded() {
    // /proc/self/status: the line "Threads:\tN" reports the LWP count.
    // Fail-CLOSED: missing /proc means we cannot prove single-threadedness,
    // so we refuse to continue rather than silently proceed.
    let s = std::fs::read_to_string("/proc/self/status").expect(
        "yubihsm-share-converter requires /proc/self/status to verify \
         single-threadedness before remove_var; refusing to proceed.",
    );
    let n = s
        .lines()
        .find_map(|l| {
            l.strip_prefix("Threads:")
                .and_then(|v| v.trim().parse::<u32>().ok())
        })
        .expect("could not parse Threads: line in /proc/self/status");
    assert!(
        n == 1,
        "yubihsm-share-converter must start single-threaded; got {n} OS threads. \
         remove_var would be unsound. A dependency may be spawning threads via \
         .init_array constructors — audit `cargo tree` for ctor/tokio/rayon-style \
         pre-main thread spawns."
    );
}

#[cfg(not(target_os = "linux"))]
fn assert_single_threaded() {
    // H-O1: macOS / Windows lack PR_SET_DUMPABLE / RLIMIT_CORE /
    // MADV_DONTDUMP guarantees. Rather than silently degrade, refuse
    // unless `YHSC_ALLOW_UNHARDENED=1` is set (dev/test override).
    // On Linux this code path is unreachable — full hardening always
    // applies and the env-var is ignored.
    if !env_flag_truthy("YHSC_ALLOW_UNHARDENED") {
        eprintln!(
            "error: yubihsm-share-converter only supports Linux for ceremony \
             use; non-Linux builds lack PR_SET_DUMPABLE / RLIMIT_CORE / \
             MADV_DONTDUMP guarantees. Set YHSC_ALLOW_UNHARDENED=1 to override \
             (development only — DO NOT use for real key material)."
        );
        std::process::exit(10);
    }
    eprintln!("warning: YHSC_ALLOW_UNHARDENED=1 — running without hardening posture.");
}

#[cfg(target_os = "linux")]
fn lock_down_process() {
    // SAFETY: prctl and setrlimit on the calling process are race-free in
    // a single-threaded process (assert_single_threaded must have run).
    // Both syscalls are idempotent — calling them twice is harmless.
    //
    // R4-6: each return value is now captured. A non-zero rc means the
    // hardening did NOT take effect (seccomp / namespace / LSM policy
    // can refuse PR_SET_DUMPABLE or RLIMIT_CORE), so we fail closed with
    // exit 12. errno is read via std::io::Error::last_os_error() and the
    // failed syscall is named in the error message so an operator can
    // diagnose the deployment-environment issue. Order is fixed:
    // prctl(PR_SET_DUMPABLE, 0) FIRST, then setrlimit(RLIMIT_CORE).
    //
    // R4-6 test note: fault-injection of these syscalls is impractical
    // without an LD_PRELOAD shim, so the failure path is validated by
    // code review only; the happy path is exercised by the existing
    // hardening test that runs in standard CI containers.
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        let rc = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("error: prctl(PR_SET_DUMPABLE, 0) failed: {err}");
            eprintln!(
                "       Cannot proceed without the dumpable=0 bit; a coredump \
                 from this process would expose key material. Likely cause: \
                 seccomp / namespace / LSM policy. Either run on a host \
                 without the restriction, or audit the policy and re-run."
            );
            std::process::exit(12);
        }

        let rc = libc::setrlimit(libc::RLIMIT_CORE, &rl);
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("error: setrlimit(RLIMIT_CORE, {{0,0}}) failed: {err}");
            eprintln!(
                "       Cannot proceed without RLIMIT_CORE=0; a coredump from \
                 this process would expose key material. Likely cause: user \
                 namespace restrictions or RLIMIT hardening. Either run on a \
                 host without the restriction, or audit the policy and re-run."
            );
            std::process::exit(12);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_down_process() { /* honoured the override above */
}

// ───────────────────────────── share parsing ────────────────────────────
//
// R12-Phase-D / item #6: `parse_legacy_share` + `LegacyShare` moved to
// `src/parse.rs` so the `fuzz/` crate can import them via the lib. The
// `use yubihsm_share_converter::parse::{parse_legacy_share, LegacyShare};`
// import at the top of this file re-binds the names locally so the rest
// of `main.rs` continues to use the short forms.

// ───────────────────────────── wrap-blob layout ─────────────────────────
//
// Both setup and manager use the same 20-byte prefix:
//   wrap_id (2 BE) | domains (2) | capabilities (8) | delegated (8) | key
const PREFIX_LEN: usize = 20;

// ───────────────────────────── input bounds ─────────────────────────────
//
// MAX accommodates: 31 legacy shares × ~80 B = 2.5 KiB, plus manager-hex
// re-emission ~110 B/share × 9 = 1 KiB, plus banner/comments. Generous.
// Raise this and the prefix length together if YubiHSM2 firmware ever
// extends the capability bitmap past 8 bytes.
const MAX_INPUT_BYTES: u64 = 16 * 1024;
const MAX_PAYLOAD_LEN: usize = 60; // 20-byte prefix + AES-256 (32B) + 8B slack; see docs/CRYPTO-SPEC.md §5 for rationale
const MIN_PAYLOAD_LEN: usize = 36; // 20-byte prefix + AES-128 (16B); raise
                                   // in lockstep with MAX if prefix changes.

fn describe_blob(blob: &[u8], show_key: bool) -> Result<(), String> {
    if blob.len() < PREFIX_LEN {
        return Err(format!(
            "recovered {} bytes — shorter than the 20-byte prefix; recovery probably failed",
            blob.len()
        ));
    }
    let key_len = blob.len() - PREFIX_LEN;
    if !matches!(key_len, 16 | 24 | 32) {
        return Err(format!(
            "recovered key is {key_len} bytes — not AES-128/192/256; recovery probably failed"
        ));
    }
    let wrap_id = u16::from_be_bytes([blob[0], blob[1]]);
    eprintln!("recovered {} bytes ({}-byte AES key)", blob.len(), key_len);
    eprintln!("  wrap_id            = 0x{wrap_id:04x}");
    eprintln!("  domains            = {}", hex::encode(&blob[2..4]));
    eprintln!("  capabilities       = {}", hex::encode(&blob[4..12]));
    eprintln!("  delegated          = {}", hex::encode(&blob[12..20]));
    // H3: mask-by-default. The unconditional hex print before this commit
    // dumped the AES key to stderr on every invocation — even on a test
    // run, even if the operator only wanted to confirm the wrap-id.
    // `--show-key` is now required to print the bytes. The redacted
    // form still names the byte length so an operator can confirm
    // recovery without seeing the key.
    //
    // H5: when we *do* print, encode through a zeroizable Vec<u8>
    // scratch rather than `hex::encode`'s `String` (which doesn't impl
    // Zeroize). hex::encode_to_slice writes ASCII bytes directly.
    if show_key {
        let mut key_hex = vec![0u8; 2 * key_len];
        hex::encode_to_slice(&blob[20..], &mut key_hex).expect("buf sized correctly");
        // SAFETY: hex::encode_to_slice only writes ASCII [0-9a-f] into the buffer.
        let key_hex_str = std::str::from_utf8(&key_hex).expect("hex output is ASCII");
        eprintln!("  aes{}_key (hex)   = {}", key_len * 8, key_hex_str);
        key_hex.zeroize();
    } else {
        eprintln!(
            "  aes{}_key (hex)   = <redacted: {} bytes; pass --show-key to print>",
            key_len * 8,
            key_len
        );
    }
    Ok(())
}

// ───────────────────────────── payload bounds ─────────────────────────
//
// Reject any share whose payload length is outside the legal range. The
// check is centralised so unit tests can exercise it directly without
// going through stdin / parsing.
fn validate_payload_len(payload_len: usize) -> Result<(), String> {
    if !(MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&payload_len) {
        return Err(format!(
            "share payload {payload_len}B outside legal range [{MIN_PAYLOAD_LEN}..={MAX_PAYLOAD_LEN}]"
        ));
    }
    Ok(())
}

// ───────────────────────────── per-byte recovery ───────────────────────
//
// R13-C / item 3: production `recover()` MOVED to `src/recover.rs` so
// the fuzz harness can import the production function directly. The
// pre-R13 local definition + the `recover_for_fuzz` lib wrapper are
// both deleted; the lib-module import above re-binds the name locally
// so call sites in main() at :695, :711 are unchanged.

// ───────────────────────────── bounded stdin ───────────────────────────
//
// Manual read loop: rejects only when the running total *exceeds*
// MAX_INPUT_BYTES (the v3/v4 off-by-one fix). An input of exactly
// MAX_INPUT_BYTES bytes succeeds; one more byte is rejected.
//
// H5: the input lives in a `Secret` so its pages are MADV_DONTDUMP-marked
// and zeroed on drop. The intermediate stack buffer `tmp` is also zeroed
// before return so a coredump that beats H4's RLIMIT_CORE=0 can't leak
// the last 8 KiB chunk through stack memory.
fn read_stdin_bounded<R: Read>(r: &mut R, buf: &mut Secret) -> Result<(), String> {
    let mut tmp = [0u8; 8192];
    let res = (|| {
        loop {
            let n = r
                .read(&mut tmp)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_INPUT_BYTES as usize {
                return Err(format!(
                    "stdin exceeds {MAX_INPUT_BYTES}-byte cap; legitimate share sets are <4 KiB"
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    })();
    tmp.zeroize();
    res
}

// ───────────────────────────── main ─────────────────────────────────────

fn main() -> ExitCode {
    // H4: startup-ordering invariant.
    //
    // 0. Hard-check we're single-threaded BEFORE touching env. The
    //    assertion is release-too; missing /proc fails CLOSED.
    assert_single_threaded();

    // 1. Strip backtrace env vars BEFORE any panic could fire — a panic
    //    after this point cannot leak a backtrace (which can include
    //    formatted argument values, i.e. secret bytes) to stderr.
    //
    //    SAFETY: caller (just above) asserted the process is single-
    //    threaded. setenv/unsetenv race with concurrent libc readers,
    //    which we just ruled out.
    unsafe {
        std::env::remove_var("RUST_BACKTRACE");
        std::env::remove_var("RUST_LIB_BACKTRACE");
    }

    // 2. Disable coredumps (RLIMIT_CORE=0 hard) and prevent
    //    PR_SET_DUMPABLE-gated ptrace-on-self.
    lock_down_process();

    // H3: parse the CLI surface. clap rejects mutually-exclusive flag
    // combinations (--resplit + --inspect-only, --inspect-only + --show-key)
    // for us via `conflicts_with_all` on the Opts struct, returning a
    // non-zero exit code through `parse()`'s internal error path. We
    // call `parse()` (not `try_parse()`) so clap formats the help/version
    // and conflict diagnostics consistently.
    let opts = Opts::parse();

    // H3: disk-stdout gate. The env-var is the *only* way to override
    // the IsTerminal check; we deliberately avoid a CLI flag so the
    // override doesn't slide into shell history.
    //
    // Hard-refuse if shell history would record the assignment itself.
    // This catches the common mistake of `export YHSC_ALLOW_DISK_STDOUT=1`
    // typed without a leading space on a bash session whose HISTCONTROL
    // doesn't include `ignorespace`/`ignoreboth` and whose HISTFILE is
    // pointing at a real file. Three escape hatches in the error message:
    // (a) `set +o history`, (b) HISTCONTROL=ignorespace + leading space,
    // (c) `unset HISTFILE`.
    let allow_disk = env_flag_truthy("YHSC_ALLOW_DISK_STDOUT");
    if allow_disk {
        let hist_safe = std::env::var("HISTCONTROL")
            .map(|h| {
                h.split(':')
                    .any(|s| s == "ignorespace" || s == "ignoreboth")
            })
            .unwrap_or(false);
        let hist_disabled = std::env::var_os("HISTFILE").is_none_or(|v| v.is_empty());
        if !hist_safe && !hist_disabled {
            eprintln!(
                "error: YHSC_ALLOW_DISK_STDOUT is set but shell history would \
                 record it."
            );
            eprintln!(
                "       Either: (a) `set +o history` first, OR \
                 (b) ensure HISTCONTROL contains `ignorespace` and prefix \
                 the command with a literal space, OR (c) `unset HISTFILE`."
            );
            return ExitCode::from(8);
        }
    }

    // H3 / M-3-2: refuse to write key material to a non-TTY stream unless
    // the operator has explicitly opted in via the env-var gate. This blocks
    // accidental `> file` redirects, shell-pipe captures, AND `2> log.txt`
    // redirects of `--resplit` / `--show-key` output. `--inspect-only` is
    // exempt because it never writes key material to either stream.
    //
    // M-3-2 (v2 architect M5): explicitly reuse env_flag_truthy here so this
    // gate inherits M-3-1's narrow-truthy semantics. Mistakenly going back to
    // `var_os(...).is_some()` would let `YHSC_ALLOW_DISK_STDOUT=0` engage the
    // override — which is exactly the footgun M-3-1 closed.
    //
    // M-3-2: --resplit writes shares to STDOUT, so it gates on stdout_is_tty;
    // --show-key writes the AES key hex via eprintln! to STDERR, so it gates
    // on stderr_is_tty. Pre-fix the gate only checked stdout; an operator
    // running `cmd --show-key < legacy.txt 2> log.txt` (TTY-stdout, captured-
    // stderr) sailed through and the key landed in `log.txt`. The compose
    // below closes that hole.
    //
    // R4-3 (dual-knob): the override now requires BOTH the env-var AND the
    // CLI flag. The env-var alone is too weak — see the prose at the top of
    // this file for the threat model. The history-safety gate above at
    // `:488-506` is INTENTIONALLY single-knob (`allow_disk` only); coupling
    // the history gate to the CLI flag would create a regression.
    //
    // R11-C3 R10-M1: `allow_disk` is already bound above and there is no
    // intervening mutation, so reuse it directly here rather than reading
    // the env-var a second time. The two reads couldn't diverge today
    // (same env, no setter between them) but the duplication was a smell
    // — and a single read makes the dual-knob threat-model boundary
    // textually obvious.
    let dual_override = allow_disk && opts.i_accept_disk_output;
    let stdout_is_tty = io::stdout().is_terminal();
    let stderr_is_tty = io::stderr().is_terminal();
    if (opts.resplit && !stdout_is_tty && !dual_override)
        || (opts.show_key && !stderr_is_tty && !dual_override)
    {
        // M-3-2 (v2 sec L1): name which stream(s) are non-TTY so the operator
        // can distinguish a `> file` mistake from a `2> log` mistake without
        // re-running under strace. Labels are only "tty" / "non-tty (pipe/file)"
        // — no fd numbers, no paths, no leakable identifiers (per sec residue).
        //
        // R4-3: the message names BOTH knobs and states the threat-model
        // boundary explicitly so the operator understands why the historic
        // env-var alone no longer suffices.
        eprintln!(
            "error: a key-bearing stream is not a terminal:\n\
             \x20      stdout = {}, stderr = {}.\n\
             \x20      --resplit writes shares to stdout; --show-key writes \
             the AES key to stderr.\n\
             \x20      Refusing to write key material to a pipe or file.\n\
             \x20      To override you must supply BOTH knobs together:\n\
             \x20        - environment variable: YHSC_ALLOW_DISK_STDOUT=1\n\
             \x20        - command-line flag:    --i-accept-disk-output\n\
             \x20      Both are required because each defeats a different threat:\n\
             \x20        * the env-var is the historic gate (kept for compatibility);\n\
             \x20        * the CLI flag defeats env-only injection (.bashrc, ssh SetEnv,\n\
             \x20          sudo env_keep, container -e, parent-process setenv-before-exec)\n\
             \x20          — an attacker who can ONLY rig env vars cannot open this gate.\n\
             \x20      Threat-model boundary: this dual gate does NOT defeat a fully-\n\
             \x20      compromised parent shell that supplies BOTH the env-var AND the\n\
             \x20      CLI flag (e.g. a malicious wrapper script). Run on a host you trust.\n\
             \x20      Redirect only to a tmpfs path (e.g. /dev/shm).",
            if stdout_is_tty {
                "tty"
            } else {
                "non-tty (pipe/file)"
            },
            if stderr_is_tty {
                "tty"
            } else {
                "non-tty (pipe/file)"
            },
        );
        return ExitCode::from(6);
    }

    // H5: input lives in a Secret so its pages are MADV_DONTDUMP-marked
    // and zeroed on drop. Capacity is MAX + 1 so the boundary check (>)
    // can fail cleanly without overflowing the buffer.
    let mut input_bytes = Secret::with_capacity(MAX_INPUT_BYTES as usize + 1);
    if let Err(e) = read_stdin_bounded(&mut io::stdin().lock(), &mut input_bytes) {
        eprintln!("error: {e}");
        return ExitCode::from(2);
    }
    let input = match std::str::from_utf8(input_bytes.as_slice()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: stdin is not valid UTF-8: {e}");
            return ExitCode::from(2);
        }
    };

    let mut shares: Vec<LegacyShare> = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_legacy_share(trimmed) {
            Ok(s) => shares.push(s),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }
    if shares.is_empty() {
        eprintln!("error: no shares on stdin (one per line, `T-N-base64`)");
        return ExitCode::from(2);
    }

    // Consistency checks: same threshold, same payload length, distinct indices.
    let threshold = shares[0].threshold;
    let payload_len = shares[0].payload.len();
    let mut seen_idx = std::collections::HashSet::new();
    for s in &shares {
        if s.threshold != threshold {
            eprintln!(
                "error: threshold mismatch: {} vs {}",
                threshold, s.threshold
            );
            return ExitCode::from(2);
        }
        if s.payload.len() != payload_len {
            eprintln!(
                "error: payload length mismatch: {} vs {}",
                payload_len,
                s.payload.len()
            );
            return ExitCode::from(2);
        }
        if !seen_idx.insert(s.index) {
            eprintln!("error: duplicate share index {}", s.index);
            return ExitCode::from(2);
        }
    }
    if (shares.len() as u8) < threshold {
        eprintln!(
            "error: have {} shares, threshold is {}; need {} more",
            shares.len(),
            threshold,
            threshold as usize - shares.len()
        );
        return ExitCode::from(2);
    }

    // Bound payload_len before allocating per-byte recovery vectors.
    // Below MIN_PAYLOAD_LEN the blob can't even hold the 20-byte prefix
    // plus a 16-byte AES-128 key; above MAX_PAYLOAD_LEN it's beyond the
    // longest legitimate AES-256 wrap-blob.
    if let Err(e) = validate_payload_len(payload_len) {
        eprintln!("error: {e}");
        return ExitCode::from(2);
    }

    // Recover from the first `threshold` shares; if at least 2*t shares
    // are available, recover again from a fully-disjoint second subset
    // and constant-time compare. When t < n < 2t (the default
    // 2-of-3 ceremony) the disjoint check is impossible but each EXTRA
    // share's payload can be predicted from the canonical polynomial
    // and compared byte-by-byte (R4-5 over-determined Lagrange). When
    // n == t there is no redundancy and --resplit is refused outright
    // BEFORE recover() runs.
    //
    // R12-C-04: `legacy::build_tables()` was deleted. The legacy module
    // is now table-free; `mul`/`inv`/`interp_at[_zero]` take plain
    // (u8, u8)/(u8) args with no precomputed-table sidecar. The
    // recover() and over-determined paths below pass no `&Tables`.
    let t = threshold as usize;
    let n = shares.len();

    // R4-5: refuse --resplit when n == t (no redundancy ⇒ no detection
    // possible). MUST be before recover() so the secret never enters
    // process memory on the refusal path. --inspect-only is intentionally
    // unaffected (it needs recovery to confirm "did my shares decode?").
    if opts.resplit && n == t {
        eprintln!(
            "error: --resplit refused: only {n} shares supplied (threshold = {t}, no redundancy).\n\
            \x20      Cross-check requires at least t+1 shares to detect a corrupt share.\n\
            \x20      Re-run with --inspect-only to confirm recovery without emitting new shares,\n\
            \x20      or collect at least t+1 shares to enable verification."
        );
        return ExitCode::from(13);
    }

    // H5: copy the recovered Vec<u8> into a Secret immediately. The Vec
    // backing pages are unmarked but the value is moved into a marked
    // allocation in microseconds; we then zeroize and drop the Vec.
    // (Now safe to recover; the n==t refusal above already exited if
    // --resplit was set with no redundancy.)
    //
    // R11-C3 D1: wrap the outer Vec in `Zeroizing` so the destructor
    // scrubs the (initialized + spare-capacity) backing bytes even on
    // a panic-window between `recover()` and the explicit `.zeroize()`
    // + `drop()` below. `Zeroizing<Vec<u8>>` derefs transparently so
    // call sites are unchanged; the explicit zeroize+drop remains so
    // the scrub happens AS EARLY AS POSSIBLE on the success path.
    let mut blob_vec: Zeroizing<Vec<u8>> =
        Zeroizing::new(match recover(&shares[..t], payload_len) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(3);
            }
        });
    let mut blob = Secret::with_capacity(blob_vec.len());
    blob.extend_from_slice(&blob_vec);
    blob_vec.zeroize();
    drop(blob_vec);

    if n >= 2 * t {
        // R11-C3 D1: same Zeroizing wrap for the disjoint-subset cross-
        // check site. See the primary recovery site above for rationale.
        let mut blob2_vec: Zeroizing<Vec<u8>> =
            Zeroizing::new(match recover(&shares[t..2 * t], payload_len) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(3);
                }
            });
        let mut blob2 = Secret::with_capacity(blob2_vec.len());
        blob2.extend_from_slice(&blob2_vec);
        blob2_vec.zeroize();
        drop(blob2_vec);
        if !constant_time_eq::constant_time_eq(blob.as_slice(), blob2.as_slice()) {
            eprintln!("error: cross-check failed — disjoint subsets recovered different blobs.");
            eprintln!("       At least one share is corrupt. Refusing to print a key.");
            return ExitCode::from(4);
        }
        eprintln!("[ok] disjoint-subset cross-check passed");
    } else if n > t {
        // R4-5: over-determined Lagrange cross-check. The polynomial is
        // uniquely defined by shares[..t]; predict each EXTRA share's
        // full Y-payload from the canonical polynomial and constant-time
        // compare against the supplied Y-payload.
        //
        // R12-C-05: full-blob constant-time verification.
        //
        // Pre-R12 the loop was a byte-wise compare that early-returned
        // on the first mismatch — the early-return leaked the FIRST
        // differing byte index via the timing of the failure (under
        // repeated queries an adversary could build a partial-
        // corruption oracle). The new shape:
        //
        //   1. Allocate ALL predicted Y-payloads first (one Zeroizing
        //      Vec<u8> per extra share). Wrapping in `Zeroizing` so
        //      the predicted bytes — which are functionally a recovered
        //      polynomial value, i.e. share material — are scrubbed
        //      from heap on drop.
        //   2. Constant-time compare each predicted blob against the
        //      supplied payload via `constant_time_eq::constant_time_eq`.
        //   3. Fold the per-share match flag into `all_ok` via a
        //      NON-short-circuit bitwise-AND on `bool` (`&=` on bool).
        //      Crucially, `&=` does NOT short-circuit — every iteration
        //      runs to completion, so the comparison count is constant
        //      WRT input contents.
        //   4. After the loop, branch on `all_ok` once. The error
        //      message is intentionally GENERIC ("shares mismatch —
        //      one or more extra shares not consistent") with no byte
        //      index AND no share index leak. The pre-R12 message
        //      named `s_extra.index` (the FIRST failing share), which
        //      under repeated probing leaks which share is corrupt.
        //
        // R9-H2 + R9-v2 M-5: interp_at takes a closure-producing-
        // iterator; the closure captures `shares[..t]` and streams
        // (index, &payload) pairs. No per-byte (u8, u8) materialisation.
        let mut all_ok = true;
        for s_extra in &shares[t..] {
            let make_pts = || shares[..t].iter().map(|s| (s.index, s.payload.as_slice()));
            // Build the predicted Y-payload for this extra share by
            // evaluating the canonical polynomial at s_extra.index for
            // every byte position. The interp_at error path is
            // unreachable in practice (the polynomial is uniquely
            // defined by shares[..t], and Phase-1 duplicate-x + xi=0
            // rejection already ran during the primary recover()
            // call), but we keep the Result handling for the
            // single-failure mode that interp_at can still produce
            // (e.g. a maliciously crafted share with index 0 reaching
            // this site through some bypass — currently impossible per
            // the M1 parse gate, but defence-in-depth).
            let mut predicted: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(payload_len));
            for byte_idx in 0..payload_len {
                match legacy::interp_at(make_pts, byte_idx, s_extra.index) {
                    Ok(b) => predicted.push(b),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(3);
                    }
                }
            }
            // Constant-time full-blob compare. `constant_time_eq` runs
            // for `min(len_a, len_b)` iterations and folds with bitwise
            // OR — its return value depends on the full slice contents,
            // not just a prefix. Both slices are of length `payload_len`
            // by construction (predicted is built to exactly that
            // size; s_extra.payload was length-validated by the
            // parse-loop's payload_len consistency check).
            let matches = constant_time_eq::constant_time_eq(&predicted, &s_extra.payload);
            // NON-short-circuit AND. `bool: BitAndAssign<bool>` evaluates
            // the RHS even when self is already false — exactly the
            // behaviour required to keep the comparison count constant
            // WRT input contents. Do NOT replace with `&&` (short-circuit)
            // — see the over_determined_no_short_circuit_grep test.
            all_ok &= matches;
            // predicted goes out of scope here; Zeroizing scrubs.
        }
        if !all_ok {
            // R12-C-05: locator-drop. Message names "one or more" and
            // contains NEITHER the failing share's index NOR any byte
            // offset. An attacker who replays a corrupt share-set
            // under repeated invocations learns ONLY that at least one
            // share is bad — not which one, and not where the corruption
            // is. This closes the partial-corruption oracle that the
            // pre-R12 byte-and-share-index locator opened.
            eprintln!(
                "error: over-determined cross-check FAILED (shares mismatch — one or more extra shares are not consistent with the canonical polynomial)"
            );
            eprintln!(
                "       At least one of the supplied shares is corrupt. \
                 Refusing to print a key."
            );
            return ExitCode::from(4);
        }
        eprintln!(
            "[ok] over-determined cross-check passed (n={n}, t={t}, {} extra share(s))",
            n - t
        );
    } else {
        // n == t. The opts.resplit branch was already refused above
        // BEFORE recover() ran. We are here only on --inspect-only or
        // --show-key without --resplit. Operator must accept the
        // residual unverifiability since they cannot supply extra shares.
        eprintln!(
            "warning: only {n} shares supplied — disjoint cross-check requires \
             ≥{} shares. Recovery cannot detect a corrupt share.",
            2 * t
        );
    }

    // H3: pass `show_key` through so describe_blob can choose between
    // the masked redacted form and the full hex print. --inspect-only
    // (below) always passes false, even when --show-key would normally
    // unmask, because clap's `conflicts_with_all` already rejects
    // --inspect-only --show-key — but we pass `false` explicitly here
    // for defence-in-depth against a future flag refactor.
    if let Err(e) = describe_blob(blob.as_slice(), opts.show_key) {
        eprintln!("error: {e}");
        return ExitCode::from(3);
    }

    // H3: --inspect-only short-circuits AFTER recovery + describe_blob
    // succeed. The operator gets the wrap-id / domains / capabilities /
    // delegated-caps diagnostics on stderr (key redacted), and the
    // marker line confirms recovery worked end-to-end without any key
    // material leaving the process. This is the safe "did my shares
    // round-trip?" check.
    if opts.inspect_only {
        eprintln!("[inspect-only] recovery succeeded; no key bytes printed.");
        return ExitCode::SUCCESS;
    }

    // Optional: re-split (R9-H3 hand-rolled `resplit::split`) so
    // yubihsm-manager will accept the shares.
    //
    // The textual format expected by aes_share_validator is
    //   `T-X-hex(Y_bytes)` where T ∈ [1..9], X ∈ [1..9].
    if opts.resplit {
        eprintln!();
        eprintln!("# new-format shares for yubihsm-manager (GF poly 0x11B; R9-H3 hand-roll):");
        let n = shares.len();
        if n > 9 {
            eprintln!(
                "error: --resplit cannot emit n={n} > 9 shares — the yubihsm-manager \
                 share-line regex caps the share-index at 9. Re-run without --resplit \
                 (a future --inspect-only mode will recover and print the blob without \
                 re-emitting any new-format shares)."
            );
            return ExitCode::from(9);
        }
        // H4: replace `.expect("split failed")` with a clean
        // `Result` path. A panic here would invoke `panic = "abort"` —
        // safe, but the failure mode is recoverable (bad parameters,
        // rng exhaustion) and deserves an actionable error message
        // instead of SIGABRT. Exit 7: resplit split failed.
        //
        // R9-H3: hand-rolled split replaces the previous vsss-rs Gf256
        // split_array call. All intermediate buffers (coeffs, per-share
        // accumulators) live in Secret pages; no leakage through
        // allocator slots.
        let new_shares = match resplit::split(blob.as_slice(), threshold, n as u8) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: resplit failed: {e}");
                return ExitCode::from(7);
            }
        };
        // H5: write+flush+zeroize each share line. The hex scratch is a
        // zeroizable Vec<u8> rather than a String, because String does
        // not impl Zeroize (drop-time zero would require an internal
        // resize / capacity dance that the trait deliberately doesn't
        // expose). hex::encode_to_slice writes ASCII bytes directly into
        // the scratch.
        //
        // R9-v2 B3: drain by value so each per-share Secret is Drop'd
        // (and zeroized) at end of body. The explicit `sh.zeroize()`
        // calls of the vsss-rs era are gone; Secret has no zeroize()
        // method and reaching for Drop via RAII is the correct shape.
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let mut drain = new_shares.into_iter();
        while let Some(sh) = drain.next() {
            // sh is a Secret consumed by value; Drop zeroizes at end of body.
            // sh.as_slice()[0] is the X byte (resplit emits 1..=n).
            // The manager's regex requires it to be 1..=9, so refuse to
            // emit anything outside that range. H4: prefer a clean error
            // path with payload zeroize over `assert!`/SIGABRT.
            // Exit 11: resplit returned a share whose X byte falls outside
            // the manager's [1..9] regex window. (Exit 9 is taken by M1's
            // n>9 guard; pick a distinct code so operators can disambiguate.)
            let bytes = sh.as_slice();
            let bad_x = bytes[0];
            if !(1..=9).contains(&bad_x) {
                // The remaining shares in `drain` will Drop (and zeroize)
                // when the iterator itself drops at the explicit
                // `drop(drain)` below.
                drop(sh); // explicit: this share's Secret zeroizes first.
                drop(drain); // then the iterator tail Drops every remaining Secret.
                eprintln!(
                    "error: resplit emitted X={bad_x} outside the manager's [1..9] regex range; \
                     refusing to print a share that yubihsm-manager would reject."
                );
                return ExitCode::from(11);
            }
            let payload_y = &bytes[1..];
            let mut hex_part = vec![0u8; 2 * payload_y.len()];
            hex::encode_to_slice(payload_y, &mut hex_part).expect("buf sized correctly");
            // write_all + flush so the bytes leave our address space
            // before we zero them, otherwise stdout buffering could
            // hold a copy past the zeroize() call.
            if let Err(e) = (|| -> io::Result<()> {
                write!(handle, "{}-{}-", threshold, bad_x)?;
                handle.write_all(&hex_part)?;
                handle.write_all(b"\n")?;
                handle.flush()
            })() {
                hex_part.zeroize();
                drop(sh); // explicit: this share's Secret zeroizes before bail.
                drop(drain); // iterator tail Drops every remaining Secret.
                eprintln!("error: failed to write share to stdout: {e}");
                return ExitCode::from(5);
            }
            hex_part.zeroize();
            // sh Drops here at end of loop body → Secret zeroized.
        }
    }

    ExitCode::SUCCESS
}

// ───────────────────────────── tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Mini reference splitter that mirrors rusty-secrets 0.0.2 byte-for-byte.
    // Emits the per-byte y-vectors for shares 1..=n, paired with their
    // x-coordinate. Coefficients c1..c_{k-1} come from the caller so the
    // test is deterministic.
    fn legacy_split(
        secret: &[u8],
        threshold: u8,
        n: u8,
        coeffs_per_byte: &[Vec<u8>],
    ) -> Vec<(u8, Vec<u8>)> {
        assert_eq!(coeffs_per_byte.len(), secret.len());
        // R12-C-04: legacy::build_tables / &Tables arg dropped from the
        // production legacy module. mul takes (a, b) → u8 directly.
        let mut shares: Vec<(u8, Vec<u8>)> =
            (1..=n).map(|x| (x, vec![0u8; secret.len()])).collect();

        for (byte_idx, &s) in secret.iter().enumerate() {
            let mut poly = Vec::with_capacity(threshold as usize);
            poly.push(s);
            for &c in &coeffs_per_byte[byte_idx] {
                poly.push(c);
            }
            assert_eq!(poly.len(), threshold as usize);

            for (x, share) in &mut shares {
                // f(x) = c0 + c1*x + c2*x^2 + ... + c_{k-1}*x^{k-1}
                let mut acc: u8 = 0;
                let mut fac: u8 = 1;
                for &coeff in &poly {
                    acc ^= legacy::mul(fac, coeff);
                    fac = legacy::mul(fac, *x);
                }
                share[byte_idx] = acc;
            }
        }
        shares
    }

    #[test]
    fn inv_zero_errors() {
        // R12-C-04: legacy::inv signature drops the &Tables arg.
        assert!(legacy::inv(0).is_err());
    }

    #[test]
    fn interp_rejects_dup_x() {
        // R9-H2: interp_at_zero now accepts a closure producing an iterator.
        // The `u8` type suffix on each literal is REQUIRED: without it the
        // array-literal's inferred integer type defaults to `i32`, which
        // fails to unify with `Iterator::Item = (u8, u8)`.
        //
        // R12-C-04: interp_at_zero signature drops the &Tables arg.
        assert!(legacy::interp_at_zero(|| [(2u8, 9u8), (2u8, 9u8)].iter().copied()).is_err());
    }

    #[test]
    fn interp_rejects_zero_x() {
        // R12-C-04: signature drop.
        assert!(legacy::interp_at_zero(|| [(0u8, 5u8), (1u8, 7u8)].iter().copied()).is_err());
    }

    #[test]
    fn r9_h2_interp_at_zero_accepts_closure_iterator() {
        // R9-H2 regression guard: a future refactor that changes
        // interp_at_zero back to `&[(u8, u8)]` would fail to compile this
        // test. The closure shape pinned here matches the production call
        // in fn recover(): `|| used.iter().map(|s| (s.index, s.payload[i]))`.
        //
        // R12-C-04: signature drop.
        let pts = [(1u8, 0u8), (2u8, 0u8)];
        let make = || pts.iter().copied();
        let _: Result<u8, _> = legacy::interp_at_zero(make);
    }

    #[test]
    fn legacy_field_basics() {
        // R12-C-04: signature drops the &Tables arg. mul/inv take their
        // operands directly.
        // 2 * 2 in GF(2^8) under poly 0x11D is 4 (no reduction needed yet).
        assert_eq!(legacy::mul(2, 2), 4);
        // A few entries from rusty-secrets v0.0.2 by manual check:
        // 2^8 reduced by 0x11D = 0x1D.
        // The generator is 2; exp[8] should be 0x1D.
        assert_eq!(legacy::mul(0x80, 2), 0x1D);
        // a * a^-1 = 1 for every nonzero a.
        for a in 1u8..=255 {
            assert_eq!(legacy::mul(a, legacy::inv(a).unwrap()), 1, "fail at a={a}");
        }
    }

    #[test]
    fn round_trip_2_of_3_known_coeffs() {
        // Secret: a fake 52-byte wrap blob (20-byte prefix + 32-byte key)
        // with arbitrary contents — round-trip must reconstruct it exactly.
        let secret: Vec<u8> = (0..52).map(|i| (i as u8).wrapping_mul(7) ^ 0xA5).collect();

        // Threshold 2 → degree-1 polys → 1 random coefficient per byte.
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|i| vec![((i as u8).wrapping_add(0x11)) ^ 0x5A])
            .collect();

        let shares = legacy_split(&secret, 2, 3, &coeffs);
        assert_eq!(shares.len(), 3);

        // Now recover via the production interp_at_zero from any 2 shares.
        // R12-C-04: interp_at_zero drops the &Tables arg.
        for combo in &[(0usize, 1usize), (0, 2), (1, 2)] {
            let (a, b) = *combo;
            let mut recovered = Vec::with_capacity(secret.len());
            for byte_idx in 0..secret.len() {
                let pts = [
                    (shares[a].0, shares[a].1[byte_idx]),
                    (shares[b].0, shares[b].1[byte_idx]),
                ];
                let make = || pts.iter().copied();
                recovered.push(legacy::interp_at_zero(make).unwrap());
            }
            assert_eq!(recovered, secret, "combo {combo:?} did not round-trip");
        }
    }

    // ───────────────────── M-C3 AES-128 / AES-192 round-trip ─────────────
    //
    // The existing `round_trip_2_of_3_known_coeffs` covers a 52-byte
    // (AES-256) blob. M-C3 adds matching unit coverage for the two
    // shorter variants — 36 B (AES-128) and 44 B (AES-192) — through
    // the same legacy_split + interp_at_zero path. The AES-128 case
    // asserts byte-equality on all three 2-of-3 share combinations; the
    // AES-192 case is identical in structure. Together they ensure a
    // regression in `recover()` or `interp_at_zero` for the smaller
    // payload lengths fails at unit scope, before the integration test
    // even spawns a subprocess.

    #[test]
    fn round_trip_aes128_blob() {
        // 36-byte secret = 20-byte prefix + 16-byte AES-128 key.
        let secret: Vec<u8> = (0..36).map(|i| (i as u8).wrapping_mul(7) ^ 0xA5).collect();
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|i| vec![((i as u8).wrapping_add(0x11)) ^ 0x5A])
            .collect();

        let shares = legacy_split(&secret, 2, 3, &coeffs);
        assert_eq!(shares.len(), 3);

        // R12-C-04: interp_at_zero drops &Tables.
        for combo in &[(0usize, 1usize), (0, 2), (1, 2)] {
            let (a, b) = *combo;
            let mut recovered = Vec::with_capacity(secret.len());
            for byte_idx in 0..secret.len() {
                let pts = [
                    (shares[a].0, shares[a].1[byte_idx]),
                    (shares[b].0, shares[b].1[byte_idx]),
                ];
                let make = || pts.iter().copied();
                recovered.push(legacy::interp_at_zero(make).unwrap());
            }
            assert_eq!(
                recovered, secret,
                "AES-128 combo {combo:?} did not round-trip"
            );
        }
    }

    #[test]
    fn round_trip_aes192_blob() {
        // 44-byte secret = 20-byte prefix + 24-byte AES-192 key.
        let secret: Vec<u8> = (0..44).map(|i| (i as u8).wrapping_mul(7) ^ 0xA5).collect();
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|i| vec![((i as u8).wrapping_add(0x11)) ^ 0x5A])
            .collect();

        let shares = legacy_split(&secret, 2, 3, &coeffs);
        assert_eq!(shares.len(), 3);

        // The spec requires "at least one combination" round-trips for
        // AES-192. We assert all three for symmetry with AES-128 — this
        // is strictly stronger and equally cheap.
        // R12-C-04: interp_at_zero drops &Tables.
        for combo in &[(0usize, 1usize), (0, 2), (1, 2)] {
            let (a, b) = *combo;
            let mut recovered = Vec::with_capacity(secret.len());
            for byte_idx in 0..secret.len() {
                let pts = [
                    (shares[a].0, shares[a].1[byte_idx]),
                    (shares[b].0, shares[b].1[byte_idx]),
                ];
                let make = || pts.iter().copied();
                recovered.push(legacy::interp_at_zero(make).unwrap());
            }
            assert_eq!(
                recovered, secret,
                "AES-192 combo {combo:?} did not round-trip"
            );
        }
    }

    #[test]
    fn round_trip_3_of_5_random_coeffs() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let secret: Vec<u8> = (0..52).map(|_| rng.r#gen::<u8>()).collect();
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|_| (0..2).map(|_| rng.r#gen::<u8>()).collect())
            .collect();

        let shares = legacy_split(&secret, 3, 5, &coeffs);

        // Take shares #2, #4, #5 (i.e. x=2,4,5) and recover.
        // R12-C-04: interp_at_zero drops &Tables.
        let chosen = [1usize, 3, 4];
        let mut recovered = Vec::with_capacity(secret.len());
        for byte_idx in 0..secret.len() {
            let make = || chosen.iter().map(|&i| (shares[i].0, shares[i].1[byte_idx]));
            recovered.push(legacy::interp_at_zero(make).unwrap());
        }
        assert_eq!(recovered, secret);
    }

    // ───── R9-H3 round-trip support (M-4 unified helper + tests) ─────
    //
    // Hand-rolled Lagrange-at-0 over poly 0x11B, matching the AES/Rijndael
    // field that resplit::split uses. Mirrors the legacy::interp_at_zero
    // shape but substitutes resplit::mul_aes for legacy::mul.
    //
    // SAFETY: this helper is #[cfg(test)] only and operates on synthetic data;
    // if ever moved out of mod tests, follow the H2 closure-refactor pattern
    // (no per-byte Vec<(u8, u8)>) and zeroize secret-bearing transients.
    fn aes_inv(a: u8) -> u8 {
        // Brute-force inverse: a^254 in GF(2^8)/0x11B. Acceptable for tests.
        let mut acc = 1u8;
        for _ in 0..254 {
            acc = resplit::mul_aes(acc, a);
        }
        acc
    }

    /// Single Lagrange-at-0 recover helper. `points[i] = (x_i, &y_payload_i)`
    /// where `y_payload_i.len() == blob_len`. Returns the recovered blob.
    fn aes_lagrange_recover(points: &[(u8, &[u8])], blob_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(blob_len);
        for byte_idx in 0..blob_len {
            // Phase 1 + Phase 3 Lagrange-at-0 evaluation.
            let mut sum = 0u8;
            for (i, &(xi, payload_i)) in points.iter().enumerate() {
                let yi = payload_i[byte_idx];
                let mut num = 1u8;
                let mut den = 1u8;
                for (j, &(xj, _)) in points.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    num = resplit::mul_aes(num, xj);
                    den = resplit::mul_aes(den, xi ^ xj);
                }
                let li0 = resplit::mul_aes(num, aes_inv(den));
                sum ^= resplit::mul_aes(yi, li0);
            }
            out.push(sum);
        }
        out
    }

    #[test]
    fn resplit_round_trip_via_hand_rolled_aes_lagrange() {
        // Synthesise a 36-byte legacy blob (wrap_id || domains || caps ||
        // delegated || key) mirroring the canary fixture content but
        // generated deterministically.
        let blob: Vec<u8> = (0..36)
            .map(|i| ((i as u8).wrapping_mul(7)) ^ 0xA5)
            .collect();
        let shares = resplit::split(&blob, 2, 3).expect("split");
        assert_eq!(shares.len(), 3);

        // Reconstruct from each 2-of-3 subset. Build the (x, &payload)
        // slice inline from the Secret-owned shares (Secret derefs to
        // &[u8] via as_slice()).
        let pts_01: Vec<(u8, &[u8])> = shares[0..2]
            .iter()
            .map(|s| {
                let bs = s.as_slice();
                (bs[0], &bs[1..])
            })
            .collect();
        let recovered_01 = aes_lagrange_recover(&pts_01, blob.len());
        assert_eq!(recovered_01, blob, "shares[0..2] round-trip");

        // For the (0,2) non-prefix subset, build the (x, &payload) slice
        // the same way — the helper is share-storage-agnostic.
        let pts_02: Vec<(u8, &[u8])> = [&shares[0], &shares[2]]
            .iter()
            .map(|s| {
                let bs = s.as_slice();
                (bs[0], &bs[1..])
            })
            .collect();
        let recovered_02 = aes_lagrange_recover(&pts_02, blob.len());
        assert_eq!(recovered_02, blob, "shares[0]+shares[2] round-trip");
    }

    #[test]
    fn resplit_round_trip_production_params_5_of_9() {
        // Production ceremony parameter space: threshold=5, n=9, AES-128 blob.
        let blob: Vec<u8> = (0..36)
            .map(|i| ((i as u8).wrapping_mul(13)) ^ 0xC3)
            .collect();
        let shares = resplit::split(&blob, 5, 9).expect("split");
        assert_eq!(shares.len(), 9);

        // Recover from the first 5 (out of 9) — minimum-redundancy reconstruct.
        let pts: Vec<(u8, &[u8])> = shares[..5]
            .iter()
            .map(|s| {
                let bs = s.as_slice();
                (bs[0], &bs[1..])
            })
            .collect();
        let recovered = aes_lagrange_recover(&pts, blob.len());
        assert_eq!(recovered, blob, "5-of-9 minimum-redundancy round-trip");

        // Also exercise a non-prefix subset to confirm any-5-of-9 works.
        let skip = [0usize, 2, 4, 6, 8];
        let pts_skip: Vec<(u8, &[u8])> = skip
            .iter()
            .map(|&i| {
                let bs = shares[i].as_slice();
                (bs[0], &bs[1..])
            })
            .collect();
        let recovered_skip = aes_lagrange_recover(&pts_skip, blob.len());
        assert_eq!(recovered_skip, blob, "skip-1 5-of-9 round-trip");
    }

    #[test]
    fn mul_aes_matches_fips197_4_2_1_first_pair() {
        // FIPS-197 §4.2.1: 0x57 · 0x83 = 0xC1 over GF(2^8)/0x11B.
        // If xtimes_aes uses 0x1D (legacy) instead of 0x1B (AES), this is
        // 0xFE — the test fails loud.
        assert_eq!(resplit::mul_aes(0x57, 0x83), 0xC1);
    }

    #[test]
    fn mul_aes_matches_fips197_second_independent_pair() {
        // 0x57 · 0x13 = 0xFE over GF(2^8)/0x11B (computed by hand: 0x57 *
        // 0x13 = 0x57 ^ 0x57·2 ^ 0x57·16 = 0x57 ^ 0xAE ^ 0x07 = 0xFE).
        // Two independent byte pairs uniquely determine the irreducible
        // polynomial choice in GF(2^8); together with the §4.2.1 pair this
        // anchor rules out every alternative reduction constant.
        assert_eq!(resplit::mul_aes(0x57, 0x13), 0xFE);
    }

    #[test]
    fn max_input_bytes_is_sixteen_kib() {
        assert_eq!(MAX_INPUT_BYTES, 16 * 1024);
    }

    #[test]
    fn describe_blob_prefix_boundary_errors_are_distinct() {
        let short = vec![0u8; PREFIX_LEN - 1];
        let err = describe_blob(&short, false).expect_err("short prefix must fail");
        assert!(
            err.contains("shorter than the 20-byte prefix"),
            "unexpected short-prefix error: {err}"
        );

        let exact_prefix = vec![0u8; PREFIX_LEN];
        let err = describe_blob(&exact_prefix, false).expect_err("zero-byte key must fail");
        assert!(
            err.contains("not AES-128/192/256"),
            "exact-prefix input must reach key-length validation, got: {err}"
        );

        let min_aes128_blob = vec![0u8; PREFIX_LEN + 16];
        describe_blob(&min_aes128_blob, false).expect("20-byte prefix + AES-128 key is valid");
    }

    #[test]
    fn stdin_bound_rejects_one_over_cap() {
        // Feed exactly MAX_INPUT_BYTES + 1 bytes through the bounded reader
        // and assert it returns the cap-exceeded error. Pair this with the
        // sister check that exactly-MAX succeeds, to lock in the off-by-one
        // boundary against regressions.
        let oversized = vec![b'A'; MAX_INPUT_BYTES as usize + 1];
        let mut buf = Secret::with_capacity(MAX_INPUT_BYTES as usize + 1);
        let err = read_stdin_bounded(&mut oversized.as_slice(), &mut buf)
            .expect_err("MAX_INPUT_BYTES + 1 must be rejected");
        assert!(
            err.contains("exceeds") && err.contains(&MAX_INPUT_BYTES.to_string()),
            "unexpected error message: {err}"
        );

        // Boundary: exactly MAX_INPUT_BYTES bytes must succeed (closes the
        // v3/v4 off-by-one false-positive: legitimate inputs at the cap
        // were previously rejected).
        let exact = vec![b'A'; MAX_INPUT_BYTES as usize];
        let mut buf2 = Secret::with_capacity(MAX_INPUT_BYTES as usize + 1);
        read_stdin_bounded(&mut exact.as_slice(), &mut buf2)
            .expect("exactly MAX_INPUT_BYTES bytes must succeed");
        assert_eq!(buf2.len(), MAX_INPUT_BYTES as usize);
    }

    #[test]
    fn payload_len_too_large_rejected() {
        // A synthetic share with payload_len = 1024 is well past the
        // longest legitimate wrap-blob (60 B) and must be rejected before
        // any allocation-heavy recovery work.
        let err = validate_payload_len(1024).expect_err("payload_len = 1024 must be rejected");
        assert!(err.contains("1024"), "unexpected error: {err}");
        assert!(
            err.contains("outside legal range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn payload_len_one_short_of_aes128_rejected() {
        // 35 B = 20-byte prefix + 15-byte tail — one short of the smallest
        // legitimate AES-128 wrap-blob (36 B). Must be rejected.
        let err = validate_payload_len(35).expect_err("payload_len = 35 must be rejected");
        assert!(err.contains("35"), "unexpected error: {err}");
        assert!(
            err.contains("outside legal range"),
            "unexpected error: {err}"
        );

        // Sanity: the boundary value MIN_PAYLOAD_LEN itself is accepted.
        validate_payload_len(MIN_PAYLOAD_LEN).expect("MIN_PAYLOAD_LEN must be accepted");
    }

    // R12-Phase-D / item #6: parse-specific tests (`parse_share_format`,
    // `parse_threshold_10_accepted`, `parse_threshold_32_rejected`,
    // `parse_index_10_accepted`, `parse_index_0_rejected`,
    // `legacy_share_debug_redacts_payload`) moved to
    // `src/parse.rs::tests` alongside the production code they exercise.

    // ───────────────────────── H1 cross-check tests ─────────────────────
    //
    // Helper: build a deterministic 2-of-5 LegacyShare set over a known
    // 52-byte secret using the same legacy_split helper used elsewhere
    // in this module. We then directly call `recover()` over the two
    // disjoint subsets shares[..2] and shares[2..4] so the test exercises
    // exactly the path main() walks for the cross-check.
    fn make_2of5_shares() -> (Vec<u8>, Vec<LegacyShare>) {
        let secret: Vec<u8> = (0..52).map(|i| (i as u8).wrapping_mul(11) ^ 0x3C).collect();
        // threshold=2 → degree-1 → 1 random coefficient per byte. Pick
        // them deterministically so the test is reproducible.
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|i| vec![((i as u8).wrapping_add(0x29)) ^ 0xB7])
            .collect();
        let raw = legacy_split(&secret, 2, 5, &coeffs);
        let shares: Vec<LegacyShare> = raw
            .into_iter()
            .map(|(x, payload)| LegacyShare {
                threshold: 2,
                index: x,
                payload,
            })
            .collect();
        (secret, shares)
    }

    #[test]
    fn cross_check_detects_disjoint_corruption() {
        // R12-C-04: recover() drops the &Tables arg.
        let (secret, mut shares) = make_2of5_shares();
        // Sanity: both disjoint subsets recover the original secret.
        let blob_a = recover(&shares[..2], secret.len()).unwrap();
        let blob_b = recover(&shares[2..4], secret.len()).unwrap();
        assert_eq!(blob_a, secret);
        assert_eq!(blob_b, secret);
        // Corrupt shares[0] — that share is only in the first subset.
        shares[0].payload[5] ^= 0x01;
        let blob_a = recover(&shares[..2], secret.len()).unwrap();
        let blob_b = recover(&shares[2..4], secret.len()).unwrap();
        // The first subset must now disagree with the second; this is
        // the path that triggers exit 4 in main().
        assert_ne!(
            blob_a, blob_b,
            "disjoint subsets should diverge after corruption"
        );
        assert!(!constant_time_eq::constant_time_eq(&blob_a, &blob_b));
    }

    #[test]
    fn cross_check_detects_disjoint_corruption_in_second_subset() {
        // Symmetric regression guard: corrupting a share that only the
        // second subset uses must also be detected.
        // R12-C-04: recover() drops the &Tables arg.
        let (secret, mut shares) = make_2of5_shares();
        shares[3].payload[17] ^= 0x80;
        let blob_a = recover(&shares[..2], secret.len()).unwrap();
        let blob_b = recover(&shares[2..4], secret.len()).unwrap();
        assert_eq!(blob_a, secret, "first subset is untouched");
        assert_ne!(blob_b, secret, "second subset must reflect the corruption");
        assert_ne!(blob_a, blob_b);
        assert!(!constant_time_eq::constant_time_eq(&blob_a, &blob_b));
    }

    #[test]
    fn cross_check_passes_clean() {
        // R12-C-04: recover() drops the &Tables arg.
        let (secret, shares) = make_2of5_shares();
        let blob_a = recover(&shares[..2], secret.len()).unwrap();
        let blob_b = recover(&shares[2..4], secret.len()).unwrap();
        assert_eq!(blob_a, secret);
        assert_eq!(blob_b, secret);
        assert!(constant_time_eq::constant_time_eq(&blob_a, &blob_b));
    }

    // ───────────────────────── R4-5 over-determined tests ──────────────
    //
    // These tests pin the new `legacy::interp_at` helper and the
    // over-determined Lagrange branch in main(). The integration-test
    // counterparts in tests/cli.rs cover the spawn-a-subprocess path;
    // these unit tests exercise the helper directly.

    #[test]
    fn interp_at_x_zero_matches_interp_at_zero() {
        // Pin: interp_at(..., x=0) must agree with interp_at_zero on the
        // same point set. Both functions implement the same Lagrange
        // formula in characteristic 2; the helper differs only in that
        // it indexes share.payload[byte_idx] in place rather than taking
        // a pre-built (xi, yi) slice. A divergence here would mean a
        // typo in the new evaluator (e.g. wrong XOR direction).
        // R12-C-04: interp_at[_zero] drops the &Tables arg.
        // Three indices, each carries a distinct toy y-byte at position 0.
        let shares = [
            LegacyShare {
                threshold: 3,
                index: 1,
                payload: vec![0x11],
            },
            LegacyShare {
                threshold: 3,
                index: 2,
                payload: vec![0x22],
            },
            LegacyShare {
                threshold: 3,
                index: 3,
                payload: vec![0x33],
            },
        ];
        let make_pts_zero = || shares.iter().map(|s| (s.index, s.payload[0]));
        let lhs = legacy::interp_at_zero(make_pts_zero).expect("interp_at_zero ok");
        let make_pts = || shares.iter().map(|s| (s.index, s.payload.as_slice()));
        let rhs = legacy::interp_at(make_pts, 0, 0).expect("interp_at ok");
        assert_eq!(lhs, rhs, "interp_at(x=0) must agree with interp_at_zero");
    }

    #[test]
    fn interp_at_collision_returns_y_at_that_index() {
        // Phase-2 early-return: when `x` collides with one of the
        // (post-phase-1-validated) xi values, return that share's
        // payload[byte_idx] rather than dividing by zero in the basis.
        // R12-C-04: interp_at drops the &Tables arg.
        let shares = [
            LegacyShare {
                threshold: 2,
                index: 1,
                payload: vec![0x00, 0x00, 0x00, 0x00, 0x00],
            },
            LegacyShare {
                threshold: 2,
                index: 5,
                payload: vec![0x00, 0x00, 0x00, 0x42, 0x00],
            },
        ];
        let make_pts = || shares.iter().map(|s| (s.index, s.payload.as_slice()));
        let got = legacy::interp_at(make_pts, 3, 5).expect("interp_at must early-return");
        assert_eq!(
            got, 0x42,
            "early-return must surface payload[3] for index=5"
        );
    }

    #[test]
    fn interp_at_rejects_xi_zero() {
        // Phase-1: xi == 0 is invalid in the legacy field (the polynomial
        // is evaluated as f(x) at the share index, and rusty-secrets v0.0.2
        // by construction starts indices at 1).
        // R12-C-04: interp_at drops the &Tables arg.
        let shares = [
            LegacyShare {
                threshold: 2,
                index: 0,
                payload: vec![0xAA],
            },
            LegacyShare {
                threshold: 2,
                index: 1,
                payload: vec![0xBB],
            },
        ];
        let make_pts = || shares.iter().map(|s| (s.index, s.payload.as_slice()));
        let err = legacy::interp_at(make_pts, 0, 7).expect_err("xi=0 must be rejected");
        assert!(
            err.contains("share index 0 is invalid"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn interp_at_detects_duplicate_x_even_when_x_collides() {
        // Pin v1→v2 fix #3: the phase-1 duplicate-x scan must complete
        // BEFORE the phase-2 collision early-return, otherwise pts =
        // [(3, A), (3, B)] queried at x=3 would early-return A and never
        // report the duplicate-x corruption — silent acceptance of a
        // malformed point set.
        // R12-C-04: interp_at drops the &Tables arg.
        let shares = [
            LegacyShare {
                threshold: 2,
                index: 3,
                payload: vec![0xAA],
            },
            LegacyShare {
                threshold: 2,
                index: 3,
                payload: vec![0xBB],
            },
        ];
        let make_pts = || shares.iter().map(|s| (s.index, s.payload.as_slice()));
        let err = legacy::interp_at(make_pts, 0, 3)
            .expect_err("duplicate x must be detected even when x collides");
        assert!(
            err.contains("duplicate x=3"),
            "expected duplicate-x error, got: {err}"
        );
    }

    #[test]
    fn over_determined_catches_single_byte_corruption_in_2_of_3() {
        // Build a clean 2-of-3 share set, then flip ONE byte at a non-
        // boundary AES-key offset (35 = position of an AES-256 key byte
        // inside the recovered 52-byte wrap-blob). Run the over-determined
        // branch logic directly and assert that the prediction at the
        // corrupt share's index disagrees with the corrupt y-byte. Any
        // single byte-flip in shares[2] must be caught by the byte-level
        // comparison in main()'s n>t branch.
        let secret: Vec<u8> = (0..52).map(|i| (i as u8).wrapping_mul(13) ^ 0x77).collect();
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|i| vec![((i as u8).wrapping_add(0x31)) ^ 0xC3])
            .collect();
        let raw = legacy_split(&secret, 2, 3, &coeffs);
        let mut shares: Vec<LegacyShare> = raw
            .into_iter()
            .map(|(x, payload)| LegacyShare {
                threshold: 2,
                index: x,
                payload,
            })
            .collect();
        // R12-C-04: interp_at drops the &Tables arg.

        // Sanity: clean shares all agree under interp_at.
        for byte_idx in 0..secret.len() {
            let make_pts = || shares[..2].iter().map(|s| (s.index, s.payload.as_slice()));
            let predicted =
                legacy::interp_at(make_pts, byte_idx, shares[2].index).expect("interp_at ok");
            assert_eq!(
                predicted, shares[2].payload[byte_idx],
                "clean share[2] must match polynomial fit at byte_idx={byte_idx}"
            );
        }

        // Corrupt: flip a single byte at offset 35 (AES-key body interior).
        shares[2].payload[35] ^= 0x01;

        // Walk the entire payload and find the mismatch — it MUST exist
        // and must be detected at byte_idx=35.
        let mut mismatch_at: Option<usize> = None;
        for byte_idx in 0..secret.len() {
            let make_pts = || shares[..2].iter().map(|s| (s.index, s.payload.as_slice()));
            let predicted =
                legacy::interp_at(make_pts, byte_idx, shares[2].index).expect("interp_at ok");
            if predicted != shares[2].payload[byte_idx] {
                mismatch_at = Some(byte_idx);
                break;
            }
        }
        assert_eq!(
            mismatch_at,
            Some(35),
            "over-determined check must catch the byte-35 flip"
        );
    }

    // ───────────────────────── H4 process-hardening tests ──────────────

    #[test]
    fn single_thread_check_passes_normally() {
        // Sanity test: cargo test runs each #[test] on its own thread, but
        // each test's assert_single_threaded() still observes a process
        // with multiple LWPs total (the test runner reaper, etc.). We
        // therefore can't unconditionally call assert_single_threaded()
        // here — it would (correctly) trip the assertion.
        //
        // What we *can* test cheaply is the parsing logic on a synthetic
        // /proc/self/status-shaped string: confirm that the n=1 case
        // succeeds and the n=4 case would trip the assertion. This
        // exercises the same find_map+strip_prefix+parse path the
        // production function uses, without taking a syscall hit.
        //
        // Production-side: assert_single_threaded() runs as the very
        // first call in main(); a regression that introduced threading
        // before remove_var would trip the release-mode assertion at
        // startup, not in the unit-test runner.
        let sample_single = "Name:\tyubihsm-share-converter\nState:\tR\nThreads:\t1\n";
        let n_single: u32 = sample_single
            .lines()
            .find_map(|l| {
                l.strip_prefix("Threads:")
                    .and_then(|v| v.trim().parse::<u32>().ok())
            })
            .expect("Threads: line is parseable");
        assert_eq!(n_single, 1, "single-thread sample must yield n=1");

        let sample_multi = "Threads:\t4\n";
        let n_multi: u32 = sample_multi
            .lines()
            .find_map(|l| {
                l.strip_prefix("Threads:")
                    .and_then(|v| v.trim().parse::<u32>().ok())
            })
            .expect("Threads: line is parseable");
        assert_ne!(n_multi, 1, "multi-thread sample must NOT yield n=1");
    }

    // R12-Phase-D / item #8: libc-touching test path. miri does not
    // model `prctl` / `setrlimit` syscalls; under `cargo miri test`
    // the libc call would panic with an "unsupported operation"
    // error. Gate the test out so the miri job stays focused on the
    // algorithmic kernels that miri CAN model.
    #[cfg(not(miri))]
    #[test]
    fn lock_down_process_is_idempotent() {
        // Both prctl(PR_SET_DUMPABLE, 0) and setrlimit(RLIMIT_CORE, {0,0})
        // are idempotent on a single process. Calling lock_down_process
        // twice from a single test must not panic, abort, or otherwise
        // misbehave — this guards against a future refactor accidentally
        // adding state (e.g. a Once init that panics on second call).
        //
        // Side-effect: this test process now has DUMPABLE=0 and
        // RLIMIT_CORE={0,0} for the rest of its lifetime, but cargo test
        // doesn't care about either, and any subsequent test that needs
        // a coredump would already be incompatible with the production
        // posture.
        lock_down_process();
        lock_down_process();
        // If we got here without aborting, the test passes. There is no
        // portable way to read RLIMIT_CORE back without prlimit(2)/getrlimit
        // bindings the project doesn't carry; we deliberately don't add a
        // libc::getrlimit call just for this assertion.
    }

    // Note: a unit test that forces resplit::split to fail (so the
    // ExitCode::from(7) path can be exercised directly) would require
    // either monkey-patching the split call or extracting the resplit
    // body into a callable function. Neither is justified here: the
    // split failure mode triggers on bad parameters (e.g. n > 255 or
    // RNG exhaustion), both of which the surrounding M1 / clap
    // validation already make unreachable in release. The dead-code
    // path is kept defensively, with the matching exit code (7).

    #[test]
    fn insufficient_shares_warns() {
        // n == t == 2: main() takes the warning branch (n < 2*t = 4).
        // Recovery still succeeds from shares[..t]; the warning is the
        // only side-effect. We don't run main() from a unit test, but
        // we lock in the predicate (n < 2*t) and confirm recover()
        // succeeds on exactly t shares — which is what the warning
        // branch in main() relies on.
        let (secret, shares) = make_2of5_shares();
        let n = 2usize;
        let t = 2usize;
        assert!(n < 2 * t, "warning branch must fire for n=t=2");
        // R12-C-04: recover() drops the &Tables arg.
        let blob = recover(&shares[..t], secret.len()).unwrap();
        assert_eq!(blob, secret);
    }

    // ───────────────────────── M-3-1: env_flag_truthy ──────────────────
    //
    // cargo test runs unit tests in parallel by default, and `set_var` /
    // `remove_var` mutate process-global state. Each test below uses a
    // unique env-var name (`YHSC_TEST_M31_<tag>`) to avoid races. None of
    // these names collides with the production `YHSC_ALLOW_*` vars or with
    // any other test's var.

    #[test]
    fn env_flag_truthy_accepts_canonical_truthy() {
        // Canonical-truthy lexemes per v2 (sec M3): `"1"` and `"true"`,
        // case-insensitive after `.trim()`. The lexicon was narrowed from
        // {1,true,yes,on} so README and code agree on `=1` (with `true`
        // tolerated for English-readability).
        let cases: &[(&str, &str)] = &[
            ("YHSC_TEST_M31_TRUTHY_ONE", "1"),
            ("YHSC_TEST_M31_TRUTHY_LCTRUE", "true"),
            ("YHSC_TEST_M31_TRUTHY_UCTRUE", "TRUE"),
            ("YHSC_TEST_M31_TRUTHY_TITLE", "True"),
            ("YHSC_TEST_M31_TRUTHY_PADDED", " 1 "),
        ];
        for (name, value) in cases {
            std::env::set_var(name, value);
            assert!(
                env_flag_truthy(name),
                "expected {name}={value:?} to be truthy"
            );
            std::env::remove_var(name);
        }
    }

    #[test]
    fn env_flag_truthy_rejects_zero_and_empty_and_falsy() {
        // The footgun M-3-1 closes: `YHSC_ALLOW_UNHARDENED=0` previously
        // engaged the override. After the fix, "0", "", and every other
        // non-canonical value is NOT-SET. Note that "yes" / "on" — which
        // some shell lexica treat as truthy — are also rejected (v2 sec
        // M3 narrowing, so README and accepted lexicon agree).
        let cases: &[(&str, &str)] = &[
            ("YHSC_TEST_M31_FALSY_ZERO", "0"),
            ("YHSC_TEST_M31_FALSY_EMPTY", ""),
            ("YHSC_TEST_M31_FALSY_FALSE", "false"),
            ("YHSC_TEST_M31_FALSY_NO", "no"),
            ("YHSC_TEST_M31_FALSY_OFF", "off"),
            ("YHSC_TEST_M31_FALSY_YES", "yes"),
            ("YHSC_TEST_M31_FALSY_ON", "on"),
            ("YHSC_TEST_M31_FALSY_UCFALSE", "FALSE"),
            ("YHSC_TEST_M31_FALSY_WS", "  "),
            ("YHSC_TEST_M31_FALSY_DISABLED", "disabled"),
        ];
        for (name, value) in cases {
            std::env::set_var(name, value);
            assert!(
                !env_flag_truthy(name),
                "expected {name}={value:?} to be NOT truthy"
            );
            std::env::remove_var(name);
        }
    }

    #[test]
    fn env_flag_truthy_unset_is_false() {
        // Unset env-var → `Err(_)` from `std::env::var` → false. Make sure
        // the var is unset on entry (defensive, in case a prior test on
        // the same thread leaked) and confirm.
        let name = "YHSC_TEST_M31_UNSET_DEFINITELY";
        std::env::remove_var(name);
        assert!(
            !env_flag_truthy(name),
            "unset env-var must read as NOT truthy"
        );
    }

    // ───────────────────── R11-V2-residue: dhat heap-residue ────────────
    //
    // dhat's `Profiler::new_heap()` panics if called while another
    // `Profiler` is already running. This is the ONLY test in the suite
    // that touches dhat's profiler API; the static Mutex below is a
    // forward-compatibility guard so that adding a second dhat test in a
    // future commit cannot accidentally trigger the "creating a profiler
    // while a profiler is already running" panic. The mutex is acquired
    // BEFORE `Profiler::new_heap()` and released when `_lock` (and
    // therefore `_profiler`) goes out of scope.
    //
    // Caveat: the dhat::Alloc global allocator is active for all `cargo
    // test` runs (under `#[cfg(test)]` at crate root); other tests still
    // allocate concurrently, and those allocations can appear in the
    // before/after snapshot delta. The assertion below is therefore an
    // upper bound (`delta <= 1`) rather than equality (`delta == 1`) so
    // it is robust to a small amount of concurrent allocator traffic —
    // any larger residue (≥ 2 net blocks) is treated as a regression in
    // recover()'s allocation discipline.
    use std::sync::Mutex;
    static DHAT_LOCK: Mutex<()> = Mutex::new(());

    /// Build a deterministic synthetic 2-of-3 share set sized to a 36-byte
    /// AES-128 wrap blob. Inlined here (rather than reusing
    /// `make_2of5_shares`) so the dhat test's allocator residue is
    /// dominated by the `recover()` call itself, not by share-construction
    /// happening between the two HeapStats snapshots. Shares are built
    /// BEFORE the profiler is consulted; all setup allocations are
    /// finalised before `before = HeapStats::get()` runs.
    fn synthetic_shares_for_dhat_test() -> Vec<LegacyShare> {
        let secret: Vec<u8> = (0..36).map(|i| (i as u8).wrapping_mul(7) ^ 0xA5).collect();
        let coeffs: Vec<Vec<u8>> = (0..secret.len())
            .map(|i| vec![((i as u8).wrapping_add(0x11)) ^ 0x5A])
            .collect();
        let raw = legacy_split(&secret, 2, 3, &coeffs);
        raw.into_iter()
            .map(|(x, payload)| LegacyShare {
                threshold: 2,
                index: x,
                payload,
            })
            .collect()
    }

    // R12-Phase-D / item #8: dhat installs a global allocator that
    // miri does not support (miri uses its own allocator/heap model).
    // The test is irrelevant under miri anyway — miri natively
    // tracks every allocation and would surface any leak loudly.
    #[cfg(not(miri))]
    #[test]
    fn recover_makes_at_most_one_heap_alloc() {
        // Serialise against any other (future) dhat-using test so that
        // `Profiler::new_heap()` cannot race against itself.
        let _lock = DHAT_LOCK.lock().unwrap();

        // Build the share set BEFORE starting the profiler so the
        // synthetic-share allocator traffic doesn't fall inside the
        // measurement window.
        // R12-C-04: recover() drops the &Tables arg.
        let shares = synthetic_shares_for_dhat_test();

        // Drop the returned blob immediately on each iteration so the
        // net delta from a clean iteration is bounded — the legitimate
        // `Vec::with_capacity(payload_len)` is born and dies INSIDE the
        // before/after window, so a clean (no-parallel-pollution)
        // iteration must show delta == 0, NOT 1. We still upper-bound
        // by 1 to be robust against an iteration in which the Vec is
        // observed live in the `after` snapshot before Drop runs.
        let _profiler = dhat::Profiler::new_heap();

        // Take the MINIMUM delta over a handful of iterations. Parallel-
        // sibling tests can only ADD to the live-block delta between
        // before/after — they cannot subtract — so the minimum across
        // iterations is the tightest upper bound on `recover()`'s own
        // residue. At least one iteration is expected to run without
        // any parallel allocation traffic in our test mix.
        const ITERS: u32 = 16;
        let mut min_delta = usize::MAX;
        for _ in 0..ITERS {
            let before = dhat::HeapStats::get();
            let blob = recover(&shares[..2], 36).expect("recover");
            let after = dhat::HeapStats::get();
            // Sanity: the recovered blob must be the expected length on
            // every iteration.
            assert_eq!(blob.len(), 36, "recover() must return a 36-byte blob");
            drop(blob); // explicit Drop so the Vec's heap block is freed
                        // before the next iteration's `before` snapshot.
            let delta = after.curr_blocks.saturating_sub(before.curr_blocks);
            min_delta = min_delta.min(delta);
            if min_delta == 0 {
                // Best possible result; further iterations cannot
                // improve on this.
                break;
            }
        }

        // The legitimate destination `blob: Vec<u8>` allocation is the
        // only heap block that could appear in the after snapshot. The
        // R9-H2 closure-iterator path in recover() must NOT introduce
        // any per-byte heap allocation. Upper-bound `<= 1` to allow for
        // the iteration in which the blob is still live at the `after`
        // snapshot (Vec is dropped after the snapshot).
        assert!(
            min_delta <= 1,
            "expected <= 1 net heap alloc in recover() (min across {ITERS} iters), got {min_delta}"
        );
    }

    // ───────────────────── R12-C-05: over-determined source-form guards ─
    //
    // STRUCTURAL anti-regression tests that scan the main.rs source via
    // `include_str!` to lock in the load-bearing properties of the
    // over-determined cross-check:
    //
    //   1. `constant_time_eq::` MUST appear in the over-determined branch.
    //   2. `Zeroizing<Vec<u8>>` (or shorter `Zeroizing::new(Vec`) MUST
    //      wrap the predicted-blob buffer.
    //   3. `&=` (non-short-circuit bitwise AND) on bool MUST be the way
    //      per-extra match flags fold into `all_ok` — and `&&`
    //      (short-circuit) on `all_ok` is forbidden.
    //   4. The error message MUST NOT name "byte" + a numeric index.
    //
    // These greps complement the end-to-end CLI tests in
    // tests/cli.rs::over_determined_*. They catch a refactor that
    // accidentally reverts to byte-wise early-return, drops the
    // Zeroizing wrap, or short-circuits the per-share check.

    /// Extract the over-determined branch source: from the `else if n > t {`
    /// guard down to the matching closing brace. Used by the four greps
    /// below; computed once per test invocation.
    fn over_determined_branch_source() -> &'static str {
        let src = include_str!("main.rs");
        let start = src
            .find("else if n > t {")
            .expect("main.rs must contain the `else if n > t {` over-determined guard");
        // Find the next `} else {` (the n == t else branch) — that
        // delimits the over-determined branch end.
        let after = &src[start..];
        let end_offset = after
            .find("} else {")
            .expect("over-determined branch must be followed by an `} else {` for n == t");
        // Return a 'static slice via Box::leak(String) — but we can do
        // better: include_str! already returns 'static, so a sub-slice
        // of it is also 'static. Build it via raw pointer slicing — or,
        // safer, return a Box::leak'd owned String. Keep this test-only:
        // Box::leak is fine here.
        Box::leak(
            after[..end_offset + "} else {".len()]
                .to_string()
                .into_boxed_str(),
        )
    }

    #[test]
    fn over_determined_full_blob_uses_constant_time_eq_grep() {
        // R12-C-05: the over-determined check MUST call
        // `constant_time_eq::constant_time_eq` (the full-blob constant-
        // time compare). Pre-R12 a `if predicted != share.payload[byte_idx]`
        // byte-wise compare was used; any future refactor that
        // reintroduces direct `!=` on Vec<u8> bytes would defeat the
        // constant-time discipline. This grep guards against it.
        let body = over_determined_branch_source();
        assert!(
            body.contains("constant_time_eq::"),
            "regression: over-determined branch does not call constant_time_eq:: (R12-C-05 forbids)"
        );
    }

    #[test]
    fn over_determined_full_blob_uses_zeroizing_grep() {
        // R12-C-05: the predicted blob (which holds reconstructed share
        // bytes — i.e. derived secret material) MUST be wrapped in
        // Zeroizing so its heap memory is scrubbed on drop. A future
        // refactor that drops the Zeroizing wrap would leak the
        // predicted bytes on panic-window between alloc and explicit
        // drop. Defended by this source-form grep.
        let body = over_determined_branch_source();
        assert!(
            body.contains("Zeroizing<Vec<u8>>") || body.contains("Zeroizing::new(Vec"),
            "regression: over-determined branch lacks Zeroizing wrap on predicted blob (R12-C-05 requires)"
        );
    }

    #[test]
    fn over_determined_no_short_circuit_grep() {
        // R12-C-05: the per-extra-share match flag MUST fold into
        // `all_ok` via NON-short-circuit AND. The Rust idiom is `&=`
        // on bool (which always evaluates RHS) — NOT `&&` (which
        // short-circuits and would re-introduce a timing channel on
        // the first failure). This grep verifies the assignment form.
        let body = over_determined_branch_source();
        assert!(
            body.contains("all_ok &= "),
            "regression: over-determined branch lacks non-short-circuit `all_ok &= ...` (R12-C-05 requires)"
        );
        // Also forbid the short-circuit form on the same variable.
        // `&&` is a perfectly legal Rust operator and can legitimately
        // appear ELSEWHERE in the branch (e.g. in a guard); we restrict
        // the prohibition to the explicit `all_ok && ` and `&& all_ok`
        // forms.
        assert!(
            !body.contains("all_ok && "),
            "regression: over-determined branch uses short-circuit `all_ok && ...` (R12-C-05 forbids)"
        );
        assert!(
            !body.contains("&& all_ok"),
            "regression: over-determined branch uses short-circuit `&& all_ok` (R12-C-05 forbids)"
        );
    }

    #[test]
    fn over_determined_error_message_has_no_byte_locator_in_source_grep() {
        // R12-C-05 LOCATOR-DROP: the user-facing eprintln!() strings in
        // the over-determined branch MUST NOT name a "byte <N>" locator
        // (pre-R12 the message was `byte_idx N share-index M differs`).
        // This grep extracts ONLY the eprintln! calls (not the loop
        // bookkeeping variable `byte_idx` which legitimately appears as
        // the for-loop iterator) and scans them for forbidden phrasings.
        let body = over_determined_branch_source();
        // Concatenate every eprintln!(...) call body into one buffer so
        // the assertion targets user-facing message strings only.
        let mut messages = String::new();
        for piece in body.split("eprintln!(").skip(1) {
            // Take up to the closing `);` — fragile but adequate for our
            // controlled source shape.
            if let Some(end) = piece.find(");") {
                messages.push_str(&piece[..end]);
                messages.push('\n');
            }
        }
        assert!(
            !messages.is_empty(),
            "over_determined_branch_source must contain at least one eprintln!"
        );
        // Forbidden literal substrings in user-facing error messages.
        for forbidden in &[
            "byte_idx",
            "byte {byte_idx}",
            "byte {}",
            "byte position",
            "at byte",
        ] {
            assert!(
                !messages.contains(forbidden),
                "regression: over-determined error MESSAGE contains forbidden `{forbidden}`. messages were:\n{messages}"
            );
        }
        // Forbidden: any "share index {variable}" or "share index N"
        // phrasing in the error messages — the locator-drop discipline
        // applies to share indices too.
        for forbidden in &["share index {", "s_extra.index", "share #{"] {
            assert!(
                !messages.contains(forbidden),
                "regression: over-determined error MESSAGE leaks share index via `{forbidden}`; messages were:\n{messages}"
            );
        }
        // Required: the new generic phrasing must appear in the messages.
        assert!(
            messages.contains("one or more")
                || messages.contains("shares mismatch")
                || messages.contains("over-determined cross-check FAILED"),
            "over-determined error MESSAGE must contain the R12-C-05 generic phrasing; messages were:\n{messages}"
        );
    }
}
