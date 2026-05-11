#!/usr/bin/env bash
# R4-2: lint gate — both fmt and clippy with -D warnings.
#
# Run from any cwd; the script cd's to its own repo root. Exits non-zero
# on any drift so the verifier protocol can use it as a single gate.
#
# Why: cargo build / test / audit do not enforce clippy --D warnings,
# so clippy lints (including MSRV violations like cap_hint.div_ceil)
# can silently accumulate. A dedicated fmt+clippy gate closes that gap.
#
# Note: a Cargo.toml [lints] table would let cargo enforce these inline,
# and is now available under the project's MSRV (R9-H1: 1.85, which is
# >= the [lints]-stable floor of Cargo 1.74). We deliberately keep the
# script gate anyway: it is the single canonical `bash scripts/tests/
# lint.sh` invocation that the verifier protocol relies on, and a script
# gate keeps cargo build / test / audit decoupled from clippy enforcement
# (which previously masked MSRV-violating lints like cap_hint.div_ceil).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

echo "[lint] cargo fmt --check"
cargo fmt --check

echo "[lint] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy --all-targets --all-features -- -D warnings

echo "[lint] all clean"
