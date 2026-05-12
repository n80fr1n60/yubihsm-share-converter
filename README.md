# yubihsm-share-converter

[![CI](https://github.com/n80fr1n60/yubihsm-share-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/n80fr1n60/yubihsm-share-converter/actions/workflows/ci.yml)
[![Coveralls](https://coveralls.io/repos/github/n80fr1n60/yubihsm-share-converter/badge.svg?branch=main)](https://coveralls.io/github/n80fr1n60/yubihsm-share-converter?branch=main)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](Cargo.toml)

> The MSRV badge is static (per `Cargo.toml` `rust-version = "1.85"`); the CI badge resolves once `ci.yml` runs for the first time; the Coveralls badge resolves once the first coverage upload lands (Coveralls auto-onboards on first push — no manual setup required).
> *Note*: identifiers like `R9-H3` below reference specific iterations of the internal security review and survive in source comments for cross-referencing; `grep -rn 'R9-H3'` from the repo root walks every annotation.

Recover YubiHSM2 wrap-key shares produced by the legacy `yubihsm-setup`
tool and re-emit them in the format `yubihsm-manager` accepts.

## Why this exists

`yubihsm-setup` and `yubihsm-manager` both implement byte-wise Shamir
secret sharing over `GF(2⁸)`, but they pick **different irreducible
polynomials** — meaning they operate in *different finite fields*:

| Tool | Library | GF(2⁸) reduction polynomial | Share encoding |
|---|---|---|---|
| `yubihsm-setup` | `rusty-secrets 0.0.2` | **`0x11D`** (Reed-Solomon / CCSDS: `x⁸+x⁴+x³+x²+1`) | `T-N-base64` (70 chars) |
| `yubihsm-manager` | `vsss-rs 5.x` (manager's bundled lib; this tool no longer depends on it as of R9-H3) | **`0x11B`** (AES / Rijndael: `x⁸+x⁴+x³+x+1`) | `T-X-hex` (72/88/104 chars) |

Same elements, different multiplication. The same `(X, Y)` points
interpolate to **different** secrets in each field. On top of that, the
manager's `aes_share_validator` regex only accepts hex (`[a-fA-F0-9]`)
and rejects base64 characters (`+`, `/`, mixed case) — so legacy shares
fail at the very first input gate.

The Yubico release notes do not flag this break. Operators with old
shares on paper will hit a wall.

## What this tool does

1. Reads legacy shares (`T-N-base64`) on stdin.
2. Lagrange-interpolates each byte at `x = 0` in the **`0x11D` field**
   to recover the original 52-byte wrap-blob (`wrap_id | domains |
   capabilities | delegated | aes_key`).
3. Sanity-checks the recovered structure (key length must be 16/24/32
   bytes; prefix must be 20 bytes).
4. With `--resplit`, re-splits the recovered blob using a hand-rolled
   `0x11B` GF(2^8) Shamir splitter (R9-H3) and prints `T-X-hex` shares
   the manager accepts.

**Recovery is cross-checked when redundancy is available**: when more than `t`
shares are supplied (`t < n ≤ 2t-1`), the converter performs byte-wise
over-determined Lagrange verification — recovering the polynomial from the
first `t` shares and checking that each remaining share's payload fits the same
polynomial. When `n ≥ 2t`, two disjoint subsets are recovered and compared in
constant time. Either path refuses to emit a key on mismatch (exit 4).
Minimum-redundancy ceremonies (`n == t`) provide no shares for verification;
`--resplit` is refused there with [exit 13](#exit-codes), and `--inspect-only`
should be used to confirm decode without emitting new shares.

## Quick start

```sh
cargo build --release
cargo test --release          # offline unit + integration tests
scripts/tests/lint.sh         # fmt + clippy -D warnings (R4-2 lint gate)

# convert and re-split for yubihsm-manager (writes shares to stdout —
# the converter refuses by default unless stdout is a TTY OR BOTH
# YHSC_ALLOW_DISK_STDOUT=1 is set in a history-safe shell AND
# --i-accept-disk-output is passed on the command line; see the
# operational hardening section below for the exact incantation)
cargo run --release -- --resplit --i-accept-disk-output < legacy.txt > converted.txt

# inspect-only mode: recover and validate, never print key bytes or
# shares. Use this to confirm a share set round-trips before committing
# to a full resplit.
cargo run --release -- --inspect-only < legacy.txt

# print the recovered AES key hex on stderr (DEFAULT IS REDACTED — you
# must opt in with --show-key, and stderr must be a TTY, or you must
# supply BOTH YHSC_ALLOW_DISK_STDOUT=1 in a history-safe shell AND
# --i-accept-disk-output on the command line).
cargo run --release -- --show-key --i-accept-disk-output < legacy.txt
```

Stderr from a successful run against the committed synthetic canary
fixture (`tests/data/toy_2of3.txt`) looks like:

```
recovered 52 bytes (32-byte AES key)
  wrap_id            = 0xa5a2
  domains            = abb0
  capabilities       = b9868f949d9ae3e8
  delegated          = f1fec7ccd5d2db20
  aes256_key (hex)   = <redacted: 32 bytes; pass --show-key to print>
```

The values shown above are the deterministic synthetic canary produced
by `cargo run --bin gen_fixture` — they have never existed on any HSM.
A live HSM ceremony (see *End-to-end HSM test* below) writes its own
runtime fixtures into `$OUT_DIR/` (`legacy.txt`, `converted.txt`, etc.)
on tmpfs and will print whatever `wrap_id` / capabilities the operator's
factory-reset HSM emitted for that ceremony.

The AES key bytes are redacted by default. Add `--show-key` to print
them on stderr. (Don't pipe `--show-key`'s stderr to a file; use the
disk-stdout gate instead — see the operational hardening section below.)

## End-to-end HSM test

The `scripts/` directory drives a complete round-trip on a real
factory-reset YubiHSM2. AES-CCM is authenticated, so a successful
unwrap at the end is **cryptographic proof of byte-for-byte wrap-key
equality** — there is no way to fake it short of breaking AES-CCM.

```sh
# 0. requires factory-reset HSM (only the default auth-key 0x0001),
#    yubihsm-connector running, and yubihsm-setup / yubihsm-shell /
#    yubihsm-manager installed (e.g. from the YubiHSM SDK .deb).

# 1. drive yubihsm-setup ksp → fresh wrap-key on the HSM + 3 legacy
#    shares; generate a victim asym key, export-wrap it, snapshot its
#    public key; then delete everything HSM-side.
# requires OUT_DIR set so stage script writes to tmpfs, not /tmp
export OUT_DIR=/dev/shm/keymat-$$
./scripts/stage_legacy_setup.sh

# 2. convert the legacy shares (R4-3 dual-knob disk-stdout gate refuses
#    output redirects unless BOTH the env-var is set in a history-safe
#    shell AND `--i-accept-disk-output` is passed on the command line —
#    see the operational hardening section below for `set +o history`
#    or HISTCONTROL=ignorespace patterns and the dual-knob rationale)
set +o history
export YHSC_ALLOW_DISK_STDOUT=1
cargo run --release -- --resplit --i-accept-disk-output \
    < "$OUT_DIR/legacy.txt" > "$OUT_DIR/converted.txt"

# 3. drive yubihsm-manager (pexpect on its cliclack TUI) to re-create
#    the wrap-key from the converted shares. YHM_SHARES_FILE is
#    required (E-M1(a) hard-fail: refuses to default to /tmp/converted.txt
#    because a same-UID attacker could pre-plant it).
YHM_SHARES_FILE="$OUT_DIR/converted.txt" \
    ./scripts/drive_manager.py

# 4. unwrap the saved blob with the manager-imported wrap-key and diff
#    the recovered public key against the pre-deletion snapshot.
./scripts/verify_roundtrip.sh
```

A clean run ends with:

```
[verify] === MATCH — wrap-key bytes are byte-for-byte identical ===
```

Verified in this repo against firmware **2.4.0**, SDK **2.7.3**,
yubihsm-manager **1.0.0**.

**Ceremony parameters** (`scripts/stage_legacy_setup.sh`): the script accepts
two env-vars to override the default 2-of-3 ceremony:

* `THRESHOLD` — minimum shares needed to recover (default: `2`).
* `N_SHARES` — total shares produced (default: `3`).

The integration E2E uses `THRESHOLD=5 N_SHARES=8` deliberately to exercise the
over-determined Lagrange branch (`t < n < 2t`). The yubihsm-manager
import format caps `n ≤ 9`; the converter refuses `--resplit` with `n > 9`
via [exit code 9](#exit-codes). For minimum-redundancy ceremonies (`n == t`),
`--resplit` exits 13 (no cross-check possible) — see [exit code 13](#exit-codes).

### What the test proves

| Stage | Mechanism | What it shows |
|---|---|---|
| `stage_legacy_setup.sh` produces shares | actual `yubihsm-setup` binary using `rusty-secrets 0.0.2` | shares are real, not synthesized |
| Converter recovers `wrap_id 0x…` matching the value `yubihsm-setup` printed | `0x11D` Lagrange interpolation | GF arithmetic is right |
| Manager regex accepts converted shares | `aes_share_validator` regex from `validators.rs:24-26` | textual format gate passes |
| Manager imports the wrap-key | full `import_from_shares` path including `vsss-rs::Gf256::combine_array` on the manager side (this tool emits shares the manager's bundled `vsss-rs` accepts; this tool itself no longer depends on `vsss-rs`) | manager pipeline accepts our output |
| `put-wrapped` of the pre-saved blob succeeds against the imported wrap-key | AES-CCM authenticated decryption with the manager-installed key | wrap-key bytes are bit-identical |

## Before you run this — operational hardening (Linux ceremony host)

The converter handles raw wrap-key material. The bullets below are not
optional on a ceremony host; they close attack surfaces the binary
cannot close from inside its own process.

```sh
# 1. Kill coredumps (both soft and hard limits)
ulimit -c 0

# 2. Strip backtrace env vars in your shell
unset RUST_BACKTRACE RUST_LIB_BACKTRACE

# 3. REQUIRED: prevent same-UID ptrace.
#    Without this, the binary's MADV_DONTDUMP / PR_SET_DUMPABLE only
#    block coredumps; a co-resident same-UID process can still attach
#    via ptrace(2) and read live RAM.
sudo sysctl -w kernel.yama.ptrace_scope=2

# 3b. RECOMMENDED: hide kernel pointers.
#     `kernel.kptr_restrict=1` (or `2`) hides kernel pointers from
#     `/proc/kallsyms` and similar interfaces, raising the bar for an
#     attacker who has gained code execution in the same UID and is
#     searching for kernel-side primitives to pivot from. Pairs
#     naturally with `ptrace_scope=2`.
sudo sysctl -w kernel.kptr_restrict=1

# 4. Tight umask, fresh per-PID tmpfs working dir.
umask 077
export OUT_DIR=/dev/shm/keymat-$$
mkdir -p "$OUT_DIR" && chmod 700 "$OUT_DIR"
trap 'shred -u "$OUT_DIR"/* 2>/dev/null; rmdir "$OUT_DIR" 2>/dev/null' EXIT

# 5. Pre-clean any leftover artefacts so each redirect creates fresh files
#    under the new umask. (`>` truncate on an existing file does NOT change
#    the file's mode.) These are the LIVE-CEREMONY runtime artefacts that
#    `stage_legacy_setup.sh` / the converter / `verify_roundtrip.sh` write
#    into the per-PID tmpfs `$OUT_DIR` — none of these names refer to any
#    committed file under `tests/data/`.
rm -f "$OUT_DIR"/{converted.txt,legacy.txt,legacy_setup_raw.log,\
                  wrapped_victim.bin,victim_pubkey.pem,victim_pubkey_final.pem}

# 6. Disable terminal multiplexers AND clipboard managers AND scrollback-to-disk:
#    - tmux: do not run inside tmux. If you must: `set -g history-file ""` in
#      tmux.conf BEFORE starting the session.
#    - iTerm2: Profiles → Terminal → uncheck "Save lines to scrollback when an
#      app status line is present" AND "Unlimited scrollback" → "Save to disk".
#    - GNOME Terminal: Edit → Preferences → Profiles → Scrolling → "Limit
#      scrollback to" = 0.
#    - X11 clipboard managers: stop them before the ceremony.
#         gpaste-client stop  ;  klipper --quit  ;  pkill xclip xsel
#      DO NOT paste shares into a TUI — type them, or read from $OUT_DIR.
#    - SSH-agent forwarding: turn it OFF for this session
#      (`ssh -a` or remove ForwardAgent from ~/.ssh/config for this host).

# 7. Disk-redirect from the converter goes through a R4-3 DUAL-KNOB gate
#    that requires BOTH the env-var AND a per-invocation CLI flag. The
#    env-var (`YHSC_ALLOW_DISK_STDOUT=1`) is the historic single-knob
#    gate, kept for compatibility; the CLI flag (`--i-accept-disk-output`)
#    defeats env-only injection vectors (.bashrc,
#    OpenSSH `SetEnv`, `sudoers env_keep`, parent-process `setenv()`
#    immediately before `exec`, container runtime `-e`). An attacker
#    who can ONLY rig env vars cannot open the gate because they cannot
#    also alter the operator's typed command line. Threat-model
#    boundary: the dual-knob does NOT defeat a fully-compromised parent
#    shell that supplies BOTH (e.g. a malicious wrapper script). The
#    binary further refuses to honor the env-var unless your shell
#    history won't record the assignment — either approach below is
#    fine for the history-safety half:

#  Option A — disable history for this shell:
set +o history
export YHSC_ALLOW_DISK_STDOUT=1
yubihsm-share-converter --resplit --i-accept-disk-output \
    < "$OUT_DIR/legacy.txt" > "$OUT_DIR/converted.txt"

#  Option B — leading-space + ignorespace HISTCONTROL:
export HISTCONTROL=ignorespace
 export YHSC_ALLOW_DISK_STDOUT=1
 yubihsm-share-converter --resplit --i-accept-disk-output \
     < "$OUT_DIR/legacy.txt" > "$OUT_DIR/converted.txt"

# 8. Air-gap or single-user host. Never write to a multi-user disk.
```

**Threat model — excluded surfaces**: this is a single-run ceremony tool,
operator-trusted host, no network surface. Timing side-channels are NOT
in scope: the converter performs lookup-table GF arithmetic (non-constant-time
by design), and the over-determined cross-check uses an early-return on the
first byte mismatch (R4-5). An attacker with sub-microsecond timing access on
a co-located process could in principle learn corruption-byte positions, but
this is acceptable given the threat model. The disjoint cross-check (`n ≥ 2t`)
does use `constant_time_eq` over the full blob.

**No-backtrace channel**: the converter is built with `panic = "abort"` (so
panics terminate the process via `SIGABRT` instead of unwinding), and
`RUST_BACKTRACE` / `RUST_LIB_BACKTRACE` are stripped from the environment
at startup. Combined with `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`, this
removes the backtrace as a key-leak channel: even on an unexpected panic,
the process dies cleanly without dumping stack frames containing share
material.

### Other notes

* `--resplit` uses `OsRng` to draw fresh polynomial coefficients.
  The new shares are unrelated to the legacy ones — the secret is
  what's preserved, not the share material itself.
* AES key bytes are redacted on stderr by default. Pass `--show-key`
  to unmask. `--inspect-only` recovers and validates the blob without
  ever printing key material; use it as a "did my shares round-trip?"
  check before committing to a full `--resplit`.
* R9-H3 (this round): the previously-large transitive tree driven by
  `vsss-rs`'s elliptic-curve features has been dropped — the resplit
  path now uses ~80 LoC of local `0x11B` Shamir (see `mod resplit` in
  `src/main.rs`). The recovered-blob bit-identity guarantee is
  preserved (verified by the FIPS-197 `mul_aes` tests + the
  production-parameter round-trip in M-7), at the cost of carrying
  ~80 LoC of audit-surface arithmetic instead of a 75-crate dep tree.
* Exit code 12 means the in-process hardening syscalls
  (`prctl(PR_SET_DUMPABLE, 0)` or `setrlimit(RLIMIT_CORE, {0,0})`)
  failed — typically because seccomp / namespace / LSM policy is
  blocking them. The converter fails closed on this path because
  proceeding would leave the process producing coredumps that expose
  key material; either run on a host without the restriction, or
  audit the policy and re-run.
* Exit code 13 means `--resplit` was requested with `n == t` (no
  redundancy). When the number of supplied shares exactly equals
  the threshold, no cross-check is mathematically possible — any
  single corrupt share defines a different polynomial that is
  consistent with every other supplied share, so re-emitting new
  shares from unverified input would silently propagate corruption.
  The converter refuses on this path BEFORE running recovery, so
  the secret is never reconstructed in process memory. Re-run with
  `--inspect-only` to confirm recovery without emitting new shares,
  or collect at least `t+1` shares to enable verification (R4-5
  byte-wise over-determined Lagrange check on the extra shares).

## Flags

The converter has three mutually-exclusive **mode flags** plus one **enabler flag**.

| Flag | Type | Description |
|---|---|---|
| `--resplit` | mode | Recover the legacy shares, then re-emit them in the GF poly `0x11B` format that `yubihsm-manager` accepts (split via the hand-rolled `mod resplit`; R9-H3). The recovered AES key itself is masked on stderr; only the new shares go to stdout. |
| `--inspect-only` | mode | Recover the legacy shares and print only structural diagnostics (wrap-id, domains, capabilities, delegated capabilities, AES key length). No key bytes and no new shares are emitted. The safe "did my shares decode?" check. |
| `--show-key` | mode | Recover the legacy shares and print the AES key hex to stderr. By default key bytes are masked (per H3 mask-by-default); this flag explicitly opts in to printing them. |
| `--i-accept-disk-output` | enabler | Required IN ADDITION to `YHSC_ALLOW_DISK_STDOUT=1` to open the disk-stdout gate (R4-3 dual-knob). Combines with any of the three mode flags. On `--inspect-only` it is operationally a no-op (no key-bearing output is produced). |

**Mutual exclusion**: `--resplit`, `--inspect-only`, and `--show-key` form a three-way exclusion via clap's `conflicts_with_all`. Passing any two together is rejected by the argument parser before any other code runs (clap exit code 2).

**Default behaviour with no mode flag**: the converter recovers and prints the same masked structural diagnostics as `--inspect-only` would — but without the explicit "I am inspecting" intent, future operator-tooling may be ambiguous about purpose. Prefer `--inspect-only` for that case.

**Disk-stdout gate (R4-3)**: a key-bearing stream (`--resplit` to stdout, or `--show-key` to stderr) that is non-tty (pipe / file / redirect) is refused unless BOTH:
1. `YHSC_ALLOW_DISK_STDOUT=1` is set in the environment, AND
2. `--i-accept-disk-output` is passed on the command line.

The env-var alone is too weak (it can be injected without operator intent via `.bashrc`, `ssh SetEnv`, `sudo env_keep`, container `-e`, parent-process setenv-before-exec). Requiring the CLI flag too defeats env-only injection; see exit code 6 in the [Exit codes](#exit-codes) table.

## Environment variables

The converter reads three environment variables. The first two are gates; the third is a hint about shell history safety.

| Variable | Lexicon | Purpose |
|---|---|---|
| `YHSC_ALLOW_DISK_STDOUT` | `1` or `true` (case-insensitive, after `trim`) — anything else (including `0`, `false`, `yes`, `on`, empty, unset) is treated as **disabled** | Half of the dual-knob disk-stdout gate (R4-3). Required IN ADDITION to `--i-accept-disk-output` to redirect a key-bearing stream to a non-tty (file / pipe). The narrow lexicon (M-3-1) prevents the `=0` "intuitively disabled" footgun from accidentally engaging the override. |
| `YHSC_ALLOW_UNHARDENED` | `1` or `true` (same lexicon) | **Dev / test only — DO NOT use for real key material.** The converter requires Linux for its hardening posture (`prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE)`, `MADV_DONTDUMP`). On macOS / Windows the converter aborts with exit 10 unless this var is set, allowing CI / development on non-Linux. |
| `HISTCONTROL` / `HISTFILE` | shell-standard | Read by the history-safety gate (R4-3 critical scoping fix: this gate is single-knob and intentionally NOT coupled to `--i-accept-disk-output`). If `YHSC_ALLOW_DISK_STDOUT=1` is set in a shell whose history would record the assignment, the converter aborts with exit 8 BEFORE reading any shares. |

**Three accepted ways to satisfy the history-safety gate** (any one works):

| Option | How | When |
|---|---|---|
| A | `set +o history` before the export | Simplest; turns shell history off entirely for the session. |
| B | `HISTCONTROL=ignorespace` + leading-space invocation | Per-line: only commands with a leading space are dropped from history. |
| C | `unset HISTFILE` | History stays in the in-memory ring buffer but is never written to disk. |

The shell-history gate is read-only on the env-vars; the converter does NOT rewrite or unset them. The operator's environment is responsible for keeping the assignments out of `~/.bash_history`. See exit codes 6, 8, 10 in the [Exit codes](#exit-codes) table.

**Threat model boundary** (R4-3): the dual-knob (`YHSC_ALLOW_DISK_STDOUT` env-var + `--i-accept-disk-output` CLI flag) defeats env-only injection vectors (`.bashrc`, `ssh SetEnv`, `sudo env_keep`, container `-e`, parent-process setenv-before-exec). It does NOT defeat a fully-compromised parent shell that supplies BOTH knobs (e.g. a malicious wrapper script). Run on a host you trust.

## Exit codes

The converter binary uses 13 distinct exit codes; the supporting scripts add a few more (documented separately at the top of each script). Codes are stable across rounds — once allocated, they keep their meaning.

| Code | Source | Meaning |
|---|---|---|
| 0 | success | Recovery + (optional) re-split + (optional) describe-blob completed cleanly. |
| 2 | parse error | Stdin line failed `T-N-base64` parse, or stdin exceeded the 16 KiB cap, or threshold/index outside `2..=31` / `1..=255`, or payload length outside `[36..60]` bytes. |
| 3 | recovery error | `legacy::interp_at_zero` returned an error (duplicate-x, x=0, or `inv(0)`), or recovered blob length is wrong, or `describe_blob` rejected the recovered AES key length. |
| 4 | cross-check failure | Either the disjoint-subset check (`n ≥ 2t`) recovered different blobs from the two halves, OR the over-determined Lagrange check (`t < n < 2t`, R4-5) found a share whose payload doesn't fit the polynomial. No key is emitted. |
| 5 | stdout write failure | Re-emitted shares failed to write to stdout (pipe closed, disk full, etc.). |
| 6 | disk-stdout gate refusal | A key-bearing stream is non-tty AND the dual-knob (`YHSC_ALLOW_DISK_STDOUT=1` env-var **and** `--i-accept-disk-output` CLI flag) was not supplied. R4-3 dual-knob; the env-var alone or flag alone is insufficient. |
| 7 | resplit split failed | `--resplit` invoked the hand-rolled `resplit::split` (R9-H3) and it returned an error (rare; bad parameters or RNG exhaustion). |
| 8 | history-safety gate refusal | `YHSC_ALLOW_DISK_STDOUT=1` was set in a shell whose history would record the assignment. The gate refuses regardless of the new CLI flag (R4-3 critical scoping fix: history gate is single-knob, intentionally). Mitigations: `set +o history`, `HISTCONTROL=ignorespace` (with leading-space invocation), or `unset HISTFILE`. |
| 9 | `--resplit` n > 9 | The yubihsm-manager wire format caps the share index at 9; re-emitting more would produce shares the manager refuses to import. |
| 10 | non-Linux without override | The hardening syscalls (`prctl`, `setrlimit`, `MADV_DONTDUMP`) are Linux-specific. macOS / Windows abort here unless `YHSC_ALLOW_UNHARDENED=1` is set (dev/test only — DO NOT use for real key material). |
| 11 | resplit X out-of-range | `--resplit` produced a share whose X coordinate is outside `[1..9]`. Defensive sanity check; never observed in practice. |
| **12** | **`lock_down_process` syscall failure (R4-6)** | `prctl(PR_SET_DUMPABLE, 0)` or `setrlimit(RLIMIT_CORE, {0,0})` returned non-zero (e.g. blocked by seccomp / namespace / LSM policy). The hardening did NOT take effect; the process aborts before any stdin read so no key material can be exposed. The error names the failed syscall and surfaces errno via `io::Error::last_os_error()`. |
| **13** | **`--resplit` n == t refusal (R4-5)** | Minimum-redundancy ceremonies (e.g. 2-of-2) provide no shares for cross-checking. The converter refuses to re-emit potentially-corrupt shares. The refusal happens **before** any `recover()` call, so the secret never enters process memory on this path. Use `--inspect-only` to confirm recovery without emitting new shares. |

## Layout

```
.
├── Cargo.toml
├── src/
│   ├── main.rs                 # converter binary + inline unit tests
│   ├── secret.rs               # page-aligned MADV_DONTDUMP buffer
│   └── bin/
│       └── gen_fixture.rs      # offline 2-of-3 toy share generator
├── tests/
│   ├── cli.rs                  # subprocess integration tests
│   └── data/                   # synthetic-only: every file is a deterministic
│       │                       # output of `cargo run --bin gen_fixture`
│       │                       # (or a non-secret demo public key).
│       ├── toy_2of3.txt              # deterministic 2-of-3 AES-256 canary
│       ├── toy_2of3_aes128.txt       # deterministic 2-of-3 AES-128 canary
│       ├── toy_2of3_aes192.txt       # deterministic 2-of-3 AES-192 canary
│       └── victim_pubkey.pem         # demo recipient key (no secret bytes;
│                                     # kept as archival ceremony scaffolding;
│                                     # not read by any code path)
├── scripts/
│   ├── stage_legacy_setup.sh   # produce legacy shares from a real HSM
│   ├── drive_manager.py        # pexpect-drive the manager's TUI
│   └── verify_roundtrip.sh     # final byte-equality check
└── README.md
```

> **Synthetic-only fixtures**: All files under `tests/data/` are
> deterministic synthetic outputs of `cargo run --bin gen_fixture` (or
> the non-secret demo `victim_pubkey.pem`). No key bytes in this repo
> have ever existed on a real HSM. The seed contract is documented at
> the top of `src/bin/gen_fixture.rs`; the canonical synthetic canary
> is `wrap_id = 0xa5a2` with the full 64-char AES-256 hex
> `29363f040d0a1318616e777c45424b5059a6afb4bdba8388919ee7ecf5f2fbc0`.
> Regenerate the fixtures from a clean checkout to verify byte-for-byte.

## Architecture, cryptography, and threat model

For a formal write-up of the cryptographic primitives, share-line wire
formats, and field-arithmetic anchors, see
[`docs/CRYPTO-SPEC.md`](docs/CRYPTO-SPEC.md). For the operator-facing
threat model — what the converter defends against, the operator
assumptions that make those defences meaningful, and the explicit
out-of-scope list — see [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
Vulnerability reporting and disclosure policy live in
[`SECURITY.md`](SECURITY.md).

## License

Apache-2.0, matching the upstream Yubico tools this interoperates with.
