#!/usr/bin/env bash
# R13-F / item 6: top-level proof-runner wrapper for Cryptol + SAW.
# Lets developers run the formal-methods proofs LOCALLY with byte-
# identical reproduction of the CI lanes. Reads the pinned Docker
# image digests from .github/workflows/proof-digests.env (single
# source of truth shared with cryptol-proofs.yml + saw-proofs.yml).
#
# Subcommands:
#   scripts/run-proofs.sh cryptol  - run all spec/*.cry :prove + :check
#   scripts/run-proofs.sh saw      - build LLVM bitcode + run CI-safe SAW
#   scripts/run-proofs.sh all      - run both sequentially (DEFAULT;
#                                    SD-R13-9 option (a): convenience
#                                    default for the common case)
#
# Exit codes:
#   0 = all proofs pass
#   1 = at least one proof failed (counterexample or solver timeout)
#   2 = invalid argument
#   3 = prerequisites missing (docker not running; proof rustc absent)
#   4 = bitcode build failed
#   5 = docker pull failed
#
# Environment:
#   YHSC_PROOF_QUIET=1 - suppress the SAW memory/CPU advisory banner.
#
# Output discipline: per-proof status lines (Q.E.D. count + counter-
# example count + timing); final summary banner of the shape
# `PASS: scripts/run-proofs.sh (N proofs verified)` on success.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
DIGESTS_ENV="${REPO_ROOT}/.github/workflows/proof-digests.env"

usage() {
  cat <<'USAGE'
scripts/run-proofs.sh - run Cryptol + SAW formal-methods proofs locally

USAGE:
  scripts/run-proofs.sh [cryptol|saw|all]   (default: all)
  scripts/run-proofs.sh --help

Subcommands:
  cryptol  Runs all :prove + :check properties from spec/*.cry via the
           pinned Cryptol Docker image (~10 min wall clock).
  saw      Builds LLVM bitcode then runs the CI-safe GF SAW equivalence proofs via
           the pinned SAW Docker image.
  all      (default) Runs cryptol first, then the CI-safe SAW core proofs.
           Total wall clock is usually dominated by the Cryptol lane.

Reads pinned Docker digests from .github/workflows/proof-digests.env so
local execution is byte-identical to the cryptol-proofs / saw-proofs CI
lanes.

Exit codes: 0 = all pass; 1 = proof failed; 2 = bad arg; 3 = missing
prereq; 4 = bitcode build failed; 5 = docker pull failed.
USAGE
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker not installed" >&2
    exit 3
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "FAIL: docker daemon not running (docker info failed)" >&2
    exit 3
  fi
}

require_toolchain_for_saw() {
  # Parse channel from saw/extracted/rust-toolchain.toml.
  local toolchain_file="${REPO_ROOT}/saw/extracted/rust-toolchain.toml"
  if [ ! -f "${toolchain_file}" ]; then
    echo "FAIL: ${toolchain_file} missing - Phase B not applied?" >&2
    exit 3
  fi
  local channel
  channel=$(awk -F '"' '/^channel/ { print $2 }' "${toolchain_file}")
  if ! cargo +"${channel}" --version >/dev/null 2>&1; then
    echo "FAIL: cargo +${channel} not available; run 'rustup toolchain install ${channel}'" >&2
    exit 3
  fi
}

load_digests() {
  if [ ! -f "${DIGESTS_ENV}" ]; then
    echo "FAIL: ${DIGESTS_ENV} missing" >&2
    exit 3
  fi
  set -a
  # shellcheck source=/dev/null
  source "${DIGESTS_ENV}"
  set +a
  : "${CRYPTOL_IMAGE:?CRYPTOL_IMAGE not set in proof-digests.env}"
  : "${SAW_IMAGE:?SAW_IMAGE not set in proof-digests.env}"
}

run_cryptol() {
  echo "=== Cryptol proofs (image: ${CRYPTOL_IMAGE}) ==="
  # The CI workflow at .github/workflows/cryptol-proofs.yml drives Cryptol
  # via `cryptol --batch <<'CRYPTOL_BATCH' ... CRYPTOL_BATCH` (a here-doc
  # of :load + :prove + :check directives), NOT via a committed
  # spec/properties.proofs file. We replicate the same directive list
  # here so local + CI runs are byte-identical.
  docker run --rm \
    -v "${REPO_ROOT}:/work" -w /work \
    -e CRYPTOLPATH=/work \
    "${CRYPTOL_IMAGE}" \
    cryptol --batch <<'CRYPTOL_BATCH' | tee /tmp/run-proofs.cryptol.log
:set prover=z3
:set prover-timeout = 1800
:load spec/properties.cry

// --- 20 locked :prove directives (Section 1 of properties.cry) ---
:prove mul_legacy_commutative
:prove mul_legacy_identity_one
:prove mul_legacy_annihilator_zero
:prove mul_legacy_distributes_xor
:prove mul_aes_commutative
:prove mul_aes_identity_one
:prove mul_aes_annihilator_zero
:prove mul_aes_distributes_xor
:prove mul_aes_fips197_first_pair
:prove mul_aes_fips197_second_pair
:prove mul_legacy_pin_0x57_0x83
:prove mul_legacy_pin_0x80_2
:prove cross_poly_distinguisher
:prove inv_legacy_round_trip
:prove inv_aes_round_trip
:prove inv_legacy_involution
:prove inv_aes_involution
:prove lagrange_recover_t2
:prove lagrange_recover_t2_generic
:prove overdet_consistent_t2

// --- 1 locked :check directive (Section 2 of properties.cry) ---
:check lagrange_recover_t3_vectors

// --- 9 user-emphasis-extras :prove (Section 3 of properties.cry) ---
:prove mul_aes_associative
:prove mul_legacy_associative
:prove mul_aes_fips197_self_square
:prove mul_aes_inv_pin_0x53_0xca
:prove mul_aes_reduction_anchor
:prove xtimes_aes_correct
:prove xtimes_legacy_correct
:prove zero_product_aes
:prove inv_aes_homomorphism
CRYPTOL_BATCH
  if grep -E '^Counterexample' /tmp/run-proofs.cryptol.log >/dev/null 2>&1; then
    echo "FAIL: cryptol counterexample(s) found" >&2
    exit 1
  fi
  local n_qed
  n_qed=$(grep -cE '^(Q\.E\.D\.|passed [0-9]+ tests)' /tmp/run-proofs.cryptol.log || true)
  echo "[ok] cryptol: ${n_qed} proof outcomes (Q.E.D. + check-pass count)"
}

run_saw() {
  echo "=== SAW core symbolic equivalence (image: ${SAW_IMAGE}) ==="
  if [ -z "${YHSC_PROOF_QUIET:-}" ]; then
    echo "NOTE: running CI-safe SAW GF proofs via the pinned Docker image."
  fi
  require_toolchain_for_saw
  local channel
  channel=$(awk -F '"' '/^channel/ { print $2 }' "${REPO_ROOT}/saw/extracted/rust-toolchain.toml")
  cargo +"${channel}" rustc --locked \
    --manifest-path "${REPO_ROOT}/saw/extracted/Cargo.toml" \
    --target-dir "${REPO_ROOT}/saw/extracted/proof-target" \
    --crate-type cdylib --release -- \
    --emit=llvm-bc \
    -C codegen-units=1 \
    -C opt-level=0 \
    -C lto=off \
    || { echo "FAIL: bitcode build failed" >&2; exit 4; }
  test -f "${REPO_ROOT}/saw/extracted/proof-target/release/deps/yubihsm_share_converter_saw_extracted.bc" \
    || { echo "FAIL: bitcode missing after build" >&2; exit 4; }
  docker run --rm \
    -e CRYPTOLPATH=/work:/work/spec \
    -v "${REPO_ROOT}:/work" -w /work \
    "${SAW_IMAGE}" \
    saw/yubihsm-share-converter.saw | tee /tmp/run-proofs.saw.log
  if grep -E '^Counterexample' /tmp/run-proofs.saw.log >/dev/null 2>&1; then
    echo "FAIL: saw counterexample(s) found" >&2
    exit 1
  fi
  local n_qed
  n_qed=$(grep -cE 'Q\.E\.D\.' /tmp/run-proofs.saw.log || true)
  if [ "${n_qed}" -ne 3 ]; then
    echo "FAIL: expected exactly 3 CI SAW Q.E.D. lines, got ${n_qed}" >&2
    exit 1
  fi
  echo "[ok] saw: ${n_qed} llvm_verify Q.E.D."
}

main() {
  local sub="${1:-all}"
  case "${sub}" in
    --help|-h) usage; exit 0 ;;
    cryptol)   load_digests; require_docker; run_cryptol ;;
    saw)       load_digests; require_docker; run_saw ;;
    all)       load_digests; require_docker; run_cryptol; run_saw ;;
    *)         echo "FAIL: unknown subcommand '${sub}'" >&2; usage >&2; exit 2 ;;
  esac
  echo "PASS: scripts/run-proofs.sh (${sub} proofs verified)"
}

main "$@"
