#!/usr/bin/env bash
# R13-F / item 6: smoke test for scripts/run-proofs.sh. Verifies the
# wrapper's flag parsing + usage banner shape. Does NOT invoke Docker
# - it's a fast structural check (under 1 s) that runs as part of the
# shell-tests CI lane (picked up via the existing scripts/tests/test_*.sh
# glob; no workflow change needed).

set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
WRAPPER="${REPO_ROOT}/scripts/run-proofs.sh"

test -f "${WRAPPER}" || { echo "FAIL: ${WRAPPER} missing"; exit 1; }
test -x "${WRAPPER}" || { echo "FAIL: ${WRAPPER} not executable"; exit 1; }

# --help returns exit 0 + emits a usage banner naming all 3 subcommands.
out=$(bash "${WRAPPER}" --help 2>&1)
echo "${out}" | grep -qF 'scripts/run-proofs.sh' || { echo "FAIL: banner missing wrapper name"; exit 1; }
echo "${out}" | grep -qE '\bcryptol\b' || { echo "FAIL: banner missing 'cryptol' subcommand"; exit 1; }
echo "${out}" | grep -qE '\bsaw\b'     || { echo "FAIL: banner missing 'saw' subcommand"; exit 1; }
echo "${out}" | grep -qE '\ball\b'     || { echo "FAIL: banner missing 'all' subcommand"; exit 1; }

# Invalid arg yields exit 2 + usage on stderr.
set +e
bash "${WRAPPER}" invalid_arg >/dev/null 2>/tmp/run-proofs.smoke.stderr
rc=$?
set -e
if [ "${rc}" -eq 0 ]; then
  echo "FAIL: invalid arg did not exit non-zero (rc=${rc})"
  exit 1
fi
if [ "${rc}" -ne 2 ]; then
  echo "FAIL: invalid arg exit code expected 2, got ${rc}"
  exit 1
fi
grep -qF 'scripts/run-proofs.sh' /tmp/run-proofs.smoke.stderr \
  || { echo "FAIL: invalid arg did not emit usage banner on stderr"; exit 1; }

echo "PASS: scripts/tests/test_run_proofs_smoke.sh (run-proofs wrapper banner OK)"
