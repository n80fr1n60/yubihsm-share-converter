# yubihsm-share-converter

This release ships a Linux binary that converts wrap-key shares produced
by the legacy `yubihsm-setup` tool (`rusty-secrets 0.0.2`, GF(2^8)
reduction polynomial `0x11D`) into the format `yubihsm-manager` accepts
(the manager bundles `vsss-rs`, GF(2^8) polynomial `0x11B`).
This converter no longer depends on `vsss-rs` (R9-H3 — see source `mod resplit` in `src/main.rs`).
The two formats are byte-incompatible at the field-arithmetic level;
this converter bridges them.

## What's in this release

- `yubihsm-share-converter` — the converter binary.
- `README.md` — operator runbook + hardening guidance + exit-code reference.
- `LICENSE` — Apache 2.0.

## Cross-distro builds

Tarballs are published per distro (Ubuntu 22.04 / 24.04, Debian 13). All x86_64.
SHA256 sums are alongside each tarball; verify via `sha256sum -c`.

## Verification

- All 3 tarballs are built inside digest-pinned distro containers (`ubuntu@sha256:...`, `debian@sha256:...`).
- Each build runs `cargo test --release --locked` + `cargo build --release --locked` (Cargo.lock-enforced).
- Pre-release gates: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit --deny warnings` all pass.

## Hardening posture (read the README)

This is a single-run ceremony tool. The README's "Operational hardening" section
describes:

- Required: `kernel.yama.ptrace_scope=2`, `kernel.kptr_restrict`.
- Dual-knob disk-output gate (`YHSC_ALLOW_DISK_STDOUT=1` env + `--i-accept-disk-output` flag).
- History-safety gate (refuses if `HISTCONTROL`/`HISTFILE` would leak the env-var to shell history).
- Linux-only; macOS / Windows refuse with exit 10 unless `YHSC_ALLOW_UNHARDENED=1` (dev/test only).

## Changelog

The per-tag commit changelog is auto-generated below.

---
