#!/usr/bin/env bash
# R13-F / item 6: top-level proof-runner wrapper for Cryptol + SAW.
# Lets developers run the formal-methods proofs LOCALLY with byte-
# identical reproduction of the CI lanes. Reads the pinned Docker
# image digests from .github/workflows/proof-digests.env (single
# source of truth shared with cryptol-proofs.yml + saw-proofs.yml).
#
# Subcommands:
#   scripts/run-proofs.sh cryptol  - run CI-safe Cryptol GF/inversion proofs
#   scripts/run-proofs.sh cryptol-offline
#                                  - run slow local Lagrange Cryptol proofs
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
# Output discipline: per-proof status lines (Cryptol Q.E.D. count, SAW
# "Proof succeeded!" count, counterexample count + timing); final summary banner of the shape
# `PASS: scripts/run-proofs.sh (N proofs verified)` on success.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
DIGESTS_ENV="${REPO_ROOT}/.github/workflows/proof-digests.env"

usage() {
  cat <<'USAGE'
scripts/run-proofs.sh - run Cryptol + SAW formal-methods proofs locally

USAGE:
  scripts/run-proofs.sh [cryptol|cryptol-offline|saw|all]   (default: all)
  scripts/run-proofs.sh --help

Subcommands:
  cryptol  Runs the CI-safe Cryptol GF/inversion proof subset via the
           pinned Cryptol Docker image.
  cryptol-offline
           Runs the slow local/offline Lagrange Cryptol obligations. These
           are intentionally excluded from the default CI gate.
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
  echo "=== Cryptol CI-safe proofs (image: ${CRYPTOL_IMAGE}) ==="
  # The pinned Cryptol image already has `cryptol` as its entrypoint. Use
  # repeated `-c` commands; `--batch` requires a file argument and does not
  # read directives from stdin.
  docker run --rm \
    -v "${REPO_ROOT}:/work" -w /work \
    -e CRYPTOLPATH=/work \
    "${CRYPTOL_IMAGE}" \
    -c ':set prover=z3' \
    -c ':set prover-timeout = 300' \
    -c ':load spec/properties.cry' \
    -c ':prove mul_legacy_commutative' \
    -c ':prove mul_legacy_identity_one' \
    -c ':prove mul_legacy_annihilator_zero' \
    -c ':prove mul_legacy_distributes_xor' \
    -c ':prove mul_aes_commutative' \
    -c ':prove mul_aes_identity_one' \
    -c ':prove mul_aes_annihilator_zero' \
    -c ':prove mul_aes_distributes_xor' \
    -c ':prove mul_aes_fips197_first_pair' \
    -c ':prove mul_aes_fips197_second_pair' \
    -c ':prove mul_legacy_pin_0x57_0x83' \
    -c ':prove mul_legacy_pin_0x80_2' \
    -c ':prove cross_poly_distinguisher' \
    -c ':prove inv_legacy_round_trip' \
    -c ':prove inv_aes_round_trip' \
    -c ':prove inv_legacy_involution' \
    -c ':prove inv_aes_involution' \
    -c ':prove mul_aes_fips197_self_square' \
    -c ':prove mul_aes_inv_pin_0x53_0xca' \
    -c ':prove mul_aes_reduction_anchor' \
    -c ':prove xtimes_aes_correct' \
    -c ':prove xtimes_legacy_correct' \
    -c ':prove zero_product_aes' \
    -c ':prove inv_aes_homomorphism' \
    | tee /tmp/run-proofs.cryptol.log
  if grep -E '^Counterexample' /tmp/run-proofs.cryptol.log >/dev/null 2>&1; then
    echo "FAIL: cryptol counterexample(s) found" >&2
    exit 1
  fi
  if grep -Ei '(^|[[:space:]])(failed|error|timed out|timeout|unknown)([[:space:].]|$)' /tmp/run-proofs.cryptol.log >/dev/null 2>&1; then
    echo "FAIL: cryptol solver-side error / timeout" >&2
    grep -Ei '(^|[[:space:]])(failed|error|timed out|timeout|unknown)([[:space:].]|$)' /tmp/run-proofs.cryptol.log >&2
    exit 1
  fi
  local n_qed
  n_qed=$(grep -cE '^Q\.E\.D\.' /tmp/run-proofs.cryptol.log || true)
  if [ "${n_qed}" -lt 24 ]; then
    echo "FAIL: expected at least 24 CI-safe Cryptol Q.E.D. lines, got ${n_qed}" >&2
    exit 1
  fi
  echo "[ok] cryptol: ${n_qed} CI-safe Q.E.D. outcomes"
}

run_cryptol_offline() {
  echo "=== Cryptol offline proofs (Lagrange + associativity; image: ${CRYPTOL_IMAGE}) ==="
  echo "NOTE: these obligations are intentionally excluded from CI; they can hit the 30-minute per-proof timeout."
  echo "      Discharges 4 Lagrange t=2/t=3 outcomes + 2 GF(2^8) associativity proofs (mul_aes_associative + mul_legacy_associative)."
  docker run --rm \
    -v "${REPO_ROOT}:/work" -w /work \
    -e CRYPTOLPATH=/work \
    "${CRYPTOL_IMAGE}" \
    -c ':set prover=z3' \
    -c ':set prover-timeout = 1800' \
    -c ':load spec/properties.cry' \
    -c ':prove lagrange_recover_t2' \
    -c ':prove lagrange_recover_t2_generic' \
    -c ':prove overdet_consistent_t2' \
    -c ':check lagrange_recover_t3_vectors' \
    -c ':prove mul_aes_associative' \
    -c ':prove mul_legacy_associative' \
    | tee /tmp/run-proofs.cryptol-offline.log
  if grep -E '^Counterexample' /tmp/run-proofs.cryptol-offline.log >/dev/null 2>&1; then
    echo "FAIL: offline cryptol counterexample(s) found" >&2
    exit 1
  fi
  if grep -Ei '(^|[[:space:]])(failed|error|timed out|timeout|unknown)([[:space:].]|$)' /tmp/run-proofs.cryptol-offline.log >/dev/null 2>&1; then
    echo "FAIL: offline cryptol solver-side error / timeout" >&2
    grep -Ei '(^|[[:space:]])(failed|error|timed out|timeout|unknown)([[:space:].]|$)' /tmp/run-proofs.cryptol-offline.log >&2
    exit 1
  fi
  local n_outcomes
  n_outcomes=$(grep -cE '^(Q\.E\.D\.|passed [0-9]+ tests)' /tmp/run-proofs.cryptol-offline.log || true)
  if [ "${n_outcomes}" -lt 6 ]; then
    echo "FAIL: expected at least 6 offline Cryptol outcomes (4 Lagrange + 2 associativity), got ${n_outcomes}" >&2
    exit 1
  fi
  echo "[ok] cryptol-offline: ${n_outcomes} offline outcomes (Lagrange + associativity)"
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
  local n_success
  n_success=$(grep -cE '^Proof succeeded! saw_(legacy_mul|resplit_mul_aes|legacy_inv)$' /tmp/run-proofs.saw.log || true)
  if [ "${n_success}" -ne 3 ]; then
    echo "FAIL: expected exactly 3 CI SAW proof-success lines, got ${n_success}" >&2
    grep -E '^(Proof succeeded!|Proving Rust|Verifying|Simulating|Checking proof obligations|Stack trace:|Error:)' /tmp/run-proofs.saw.log >&2 || true
    exit 1
  fi
  echo "[ok] saw: ${n_success} llvm_verify proofs succeeded"
}

main() {
  local sub="${1:-all}"
  case "${sub}" in
    --help|-h) usage; exit 0 ;;
    cryptol)         load_digests; require_docker; run_cryptol ;;
    cryptol-offline) load_digests; require_docker; run_cryptol_offline ;;
    saw)             load_digests; require_docker; run_saw ;;
    all)             load_digests; require_docker; run_cryptol; run_saw ;;
    *)         echo "FAIL: unknown subcommand '${sub}'" >&2; usage >&2; exit 2 ;;
  esac
  echo "PASS: scripts/run-proofs.sh (${sub} proofs verified)"
}

main "$@"
