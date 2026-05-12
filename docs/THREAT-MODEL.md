# Threat Model — yubihsm-share-converter

This document is the operator-facing companion to the inline `H-`/`R-`/`M-`
prefix comments scattered through the source. It states what the converter
defends against, what it does NOT, and the assumptions that make the
defended threats meaningful. Every defence listed here has a load-bearing
implementation site in the codebase; the cited `file:line` anchors point at
the current production text.

## 1. Operator assumptions

The converter is designed for a single, ceremony-style invocation by a
trusted operator. The threat model below is valid only when ALL of the
following hold:

- **Single-run ceremony.** The converter is invoked once per share set.
  No multi-run "split the recover step across processes" workflow is
  supported (see `src/main.rs:805-841` for the over-determined cross-check
  that consumes all supplied shares in one pass).
- **Air-gapped host OR `kernel.yama.ptrace_scope = 2`.** Either the host
  has no network access during recover/resplit (preferred), or the kernel
  refuses cross-process `PTRACE_ATTACH` even within the same UID. The
  converter's in-process scrubbing (zeroize on drop, page-aligned `Secret`
  pages with `MADV_DONTDUMP`) defends against postmortem snooping; it
  cannot defend against a live attached debugger.
- **No network access during recover/resplit.** The converter performs no
  outbound I/O of its own; the assumption is operational — the host's
  network is disabled (firewall, unplugged cable, or air gap) so that
  ambient ceremony state cannot leak.
- **Same-UID process boundary is trusted.** Other processes running under
  the same UID could, in principle, read the converter's memory via
  `/proc/self/mem` or `process_vm_readv`. The Yama ptrace gate above is
  the kernel-side mitigation; the operational assumption is that the
  ceremony host is dedicated to this purpose and no untrusted same-UID
  code is running concurrently.
- **Root is not actively adversarial but is not blindly trusted.** A
  fully-compromised root (kernel rootkit, malicious LKM) is out of scope.
  The converter does NOT attempt to defeat root; it does however refuse
  to write key material to disk under a passive-mistake threat profile
  (the dual-knob `YHSC_ALLOW_DISK_STDOUT` env + `--i-accept-disk-output`
  CLI gate at `src/main.rs:891-911, 940-942`).
- **Operator does NOT redirect stdout to disk by mistake.** The
  dual-knob disk-stdout gate (above) enforces this — both knobs must be
  set deliberately, in a history-safe shell, before the converter will
  emit shares to a non-TTY stdout.

## 2. Threats defended against

Each item below cites the load-bearing implementation site.

1. **RLIMIT_CORE-bypassed coredumps that include `Secret` pages.**
   Defence: `H4` triple — `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, and
   `MADV_DONTDUMP` on every `Secret` allocation (`src/secret.rs:117-139`).
   Even if a kernel module or `setrlimit` race re-enables coredumps,
   `MADV_DONTDUMP` excludes the page range from the dump file.

2. **Panic-backtrace leakage of share/payload bytes.** Defence:
   `panic = "abort"` in the release profile (`Cargo.toml:43`) — there is
   no unwinder, so no `{:?}` formatter is invoked at panic time. As
   defence-in-depth, the `LegacyShare` type has a hand-rolled `Debug`
   impl (`src/main.rs:299-310`) that redacts the payload field, so an
   accidental `dbg!(share)` cannot leak share bytes even under
   `panic = "unwind"` configurations of downstream consumers.

3. **Naive swap-to-disk of secrets.** Defence: `MADV_DONTDUMP` (above)
   plus page-aligned `Secret` allocations (`src/secret.rs:76-149`) so that
   the advice covers exactly the secret-bearing pages and nothing else.
   Drop scrubs every secret-bearing buffer (`src/secret.rs:202-233`); the
   recovery destinations on the call-path are wrapped in
   `Zeroizing<Vec<u8>>` (`src/main.rs:770, :786`). The converter does NOT
   attempt to `mlock` pages — `mlock` is an operator decision; see the
   "operational hardening" section of `README.md`.

4. **Cache-timing attack on the GF mul operand.** Defence: R11-C2
   branchless Russian-peasant multiplication in BOTH fields —
   `legacy::mul` at `src/legacy.rs:49-62` (poly 0x11D) and
   `resplit::mul_aes` (poly 0x11B). R12-04 extends the branchless shape
   to `legacy::inv` (a^254 via repeated mul; constant-time independent of
   operand). Neither multiplication function takes a branch on a secret
   bit, so the table-walk timing channel that plagued the pre-R11
   tabular form is closed.

5. **Partial-corruption oracle via per-byte cross-check diagnostics.**
   Defence: R12-05 — the over-determined cross-check at
   `src/main.rs:805-841` no longer names the failing byte index in any
   error message; the share index IS named (it's public — it appears
   verbatim in the share-line format). On repeated submissions of
   partially-corrupted share sets, the operator learns at most "share K
   doesn't fit the polynomial", never "byte B of share K is the divergent
   byte". This denies a search-by-bisection oracle.

6. **Heap residue across recovery.** Defence: R11-C5 dhat-instrumented
   regression test (`recover_makes_at_most_one_heap_alloc` in
   `src/main.rs` test module) asserts that `recover()` performs at most
   one heap allocation block delta. The destination `Vec` is the only
   allowed allocation; intermediate per-byte materialisation is denied at
   the type level by the iterator-returning-closure shape of
   `legacy::interp_at_zero` (`src/legacy.rs:99-141`).

7. **Same-UID process snooping during a multi-step ceremony.** This is
   explicitly **out of scope** for the converter itself; the operator
   assumption (single-run, single-process) takes the threat off the
   table. The Yama ptrace gate (operator assumption #2) plus the
   dedicated-ceremony-host posture handle the operational risk.

8. **Shell-history-file leakage of secrets typed on the command line.**
   Defence: H-1 dual-knob disk-stdout gate (`src/main.rs:891-911, :940-942`)
   refuses non-TTY stdout unless BOTH `YHSC_ALLOW_DISK_STDOUT=1` AND
   `--i-accept-disk-output` are present. The env-var-only path is
   refused, so a `.bashrc` `export YHSC_ALLOW_DISK_STDOUT=1` accident
   cannot silently enable disk output. The same module performs a
   defensive `HISTFILE` / `HISTCONTROL` inspection at `src/main.rs:488-506`
   (read-stdin tmp scrub at the read boundary so even a pre-empted read
   leaves no residue in the stack tmp buffer).

9. **Share-line leakage through the manager-TUI pexpect mirror.**
   Defence: H-S2 share-shape regex scrub at
   `scripts/drive_manager.py:160-235` redacts the share-line shape
   `T-X-hex{≥40}` from the pexpect mirror stream before it reaches stdout
   or the log file. The mirror is otherwise verbatim — operators need it
   to debug TUI drift — so the scrub is narrowly targeted at the share
   shape.

## 3. Out of scope

The following are explicitly NOT defended against by this converter:

1. **SLSA build provenance.** Per maintainer directive, SLSA-style
   provenance attestation is not in scope for this project. Reproducible
   builds via `Cargo.lock` + the pinned MSRV + the locked-pin CI matrix
   are the available transparency layer.
2. **Binary signing.** Per maintainer directive, signed-release artefacts
   are not in scope. Distribution is source-only; downstream packagers
   own the signing posture for their platforms.
3. **Side-channel attacks against physical YubiHSM hardware.** EM
   emanation, power analysis, fault injection against the HSM itself —
   vendor-domain, not converter-domain.
4. **Physical-side-channel attacks against the ceremony host.** TEMPEST,
   acoustic, power-trace attacks against the host CPU running the
   converter — out of scope; requires hardware-level countermeasures
   (Faraday cage, filtered power) outside the software boundary.
5. **Supply-chain attacks against the Rust toolchain itself.** The CI
   matrix pins `rustup-init` by sha256 and the project pins MSRV at 1.85
   (`Cargo.toml:14`); toolchain provenance upstream of that pin is
   outside our remit.
6. **Kernel exploits / root-level adversary.** A compromised kernel or
   a root-level attacker can defeat every userland mitigation in the
   converter (`/proc/self/mem`, kernel LKM, eBPF). The dedicated
   ceremony-host posture is the only mitigation.
7. **Cold-boot attacks against host RAM.** An attacker with physical
   access to the host's RAM during or immediately after the ceremony can,
   in principle, recover residual key material from DRAM cells. Defeating
   this requires hardware-level countermeasures (memory encryption,
   chilled-RAM detection) that are outside the converter's scope.
8. **Multi-run ceremonies.** The converter is single-shot by design; a
   "recover today, resplit next week from saved intermediate state"
   workflow is not supported and not defended against. The operator
   assumption above closes this.

## 4. Residual risks

The Shamir secret sharing primitive at the heart of the converter is
**information-theoretically secure**: there is no computational hardness
assumption that could degrade with future advances in cryptanalysis. The
residual risk surface is therefore entirely **operational** — the
converter's correctness depends on the operator following the runbook
(`README.md` operational-hardening section), running on a host that
satisfies the assumptions in §1, and not deliberately bypassing the
dual-knob disk-stdout gate.

Specific operational residues:

- **The disk-stdout gate is defeatable by a fully-compromised parent
  shell.** A malicious wrapper that supplies BOTH knobs and feeds the
  converter a forged TTY can capture stdout. The gate defends only
  against ambient-environment slip; it cannot defend against an adversary
  with shell-level control of the parent process. (`README.md:354` notes
  this explicitly.)
- **The recover step is gated by the over-determined cross-check only
  when `n > t`.** A 2-of-2 share set has no extra share to predict
  against; the operator is warned at `src/main.rs:851-853` and the
  recovery proceeds without a corrupt-share detector. The runbook
  recommends `n ≥ t + 1` for any ceremony that needs end-to-end
  share-integrity assurance, and `n ≥ 2t` for the strictly stronger
  disjoint-subset cross-check (`src/main.rs:783-803`).
- **Side-channel exposure on non-x86_64 architectures.** The branchless
  GF arithmetic is constant-time on the architectures we've measured
  (x86_64, aarch64). On exotic targets (e.g. older ARMv7 without barrel
  shifters), the constant-time property is asserted by the reference
  test but has not been benchmarked end-to-end. Out-of-scope-ish — the
  converter is built for ceremony hosts that almost universally run
  x86_64.
