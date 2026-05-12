#!/usr/bin/env bash
# R12-01 / R12-02: anti-R10-L2 methodology gate.
#
# Audits every shell-out parser in scripts/ against the canonical
# device-transcript fixtures at tests/fixtures/device-transcripts/. The
# fixtures use the real upstream output format (post-R10-L2-hotfix
# `id: 0xXXXX, type: T, algo: A, sequence: 0, label: L` for list-objects).
#
# **The gate is load-bearing because it reads the PARSER PATTERNS DIRECTLY
# FROM THE PRODUCTION SCRIPTS** (via grep) — if a maintainer ever reverts a
# parser back to a pre-hotfix shape (e.g. `/^wrap-key,/` substring match),
# this test will FAIL loudly because the extracted pattern then yields the
# wrong value when run against the fixture. The test does NOT copy the
# parser patterns into its own body; it locates them in production
# source and executes them in-place.
#
# Maintenance: when upstream yubihsm-shell / yubihsm-setup /
# yubihsm-manager change their output format, regenerate the fixture
# from a SYNTHETIC-ID-stuffed device (canary 0xa5a2, NEVER a real
# capture) and update both the parser AND the fixture in lockstep. The
# fixture README documents the synthetic-discipline policy.
#
# This gate exists because the R10-L2 carry-over taught us the bitter
# lesson: a parser-shaped test stub that mirrors the parser's bug
# stays green. Only a canonical transcript that BOTH the parser AND
# the test consume can detect the divergence.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
FIXTURES="${REPO_ROOT}/tests/fixtures/device-transcripts"
STAGE_SH="${REPO_ROOT}/scripts/stage_legacy_setup.sh"
EXTRACT_SH="${REPO_ROOT}/scripts/_extract_shares.sh"
VERIFY_SH="${REPO_ROOT}/scripts/verify_roundtrip.sh"
DRIVER_PY="${REPO_ROOT}/scripts/drive_manager.py"

# Sanity-check the fixture directory + production scripts.
[ -d "${FIXTURES}" ] || { echo "FAIL: fixtures dir missing: ${FIXTURES}" >&2; exit 1; }
for f in yubihsm-shell-list-objects.txt yubihsm-setup-ksp.txt \
         yubihsm-shell-put-wrapped-ok.txt yubihsm-shell-put-wrapped-authfail.txt \
         yubihsm-shell-get-public-key.txt yubihsm-manager-tui-prompts.txt; do
    [ -r "${FIXTURES}/${f}" ] || { echo "FAIL: missing fixture: ${f}" >&2; exit 1; }
done
for f in "${STAGE_SH}" "${EXTRACT_SH}" "${VERIFY_SH}" "${DRIVER_PY}"; do
    [ -r "${f}" ] || { echo "FAIL: production script missing: ${f}" >&2; exit 1; }
done

# Synthetic-discipline gate: refuse if a real-device hex id snuck in.
# Allow-list: 0x0001 (real factory default — never secret), 0xa5a2
# (canary), 0xc995 (app-auth), 0x0042 (victim asym). The R10-L2 foil
# 0xDEAD is uppercase deliberately so this lowercase-hex grep skips it.
unexpected_ids=$(grep -rE '0x[0-9a-f]{4}' "${FIXTURES}/" | grep -vE '0x0001|0xa5a2|0xc995|0x0042' || true)
if [ -n "${unexpected_ids}" ]; then
    echo "FAIL: synthetic-discipline violation — unexpected 0xNNNN ids in fixtures:" >&2
    printf '%s\n' "${unexpected_ids}" >&2
    exit 1
fi

PARSERS_VERIFIED=0
fail() { echo "FAIL [$1]: $2" >&2; exit 1; }

# Helper: extract the awk PROGRAM (the body in the second single-quoted
# segment of `awk -F'[, ]+' '...'`) from a production source line. Each
# parser site is identified by a "needle" substring of the surrounding
# code. The awk-field-split on `'` decomposes the line as:
#   field 1: leading text up to first `'`
#   field 2: contents of `-F'...'` (i.e. `[, ]+`)
#   field 3: whitespace between the two quoted segments
#   field 4: the awk PROGRAM BODY (what we want)
#   field 5: trailing pipe/redirect/etc.
# If the production source ever drifts (e.g. someone reverts the column
# anchor back to the pre-R10-L2 substring form), field 4 changes and the
# parity checks below FAIL — that's the entire purpose of this gate.
extract_awk() {
    local file="$1" needle="$2"
    # Tolerate "needle not found": grep returns 1 on no-match, and we
    # rely on the empty-string check at the call site to detect the
    # injected-regression case (where the production source has been
    # reverted to a pre-hotfix shape that doesn't match the needle).
    # Without the `|| true`, set -e + pipefail would abort the script
    # silently BEFORE the call site's `[ -z "..." ]` guard fires.
    { grep -F -- "${needle}" "${file}" || true; } \
        | head -n 1 \
        | awk -F"'" '{print $4}'
}

# =====================================================================
# Parser 1: stage_legacy_setup.sh:173 — `grep -c '^id:'` for object count.
# =====================================================================
# Locate the production grep invocation and confirm it counts the
# correct number of objects against the fixture. We assert the grep
# is anchored on `^id:` (not, say, `id:`) to catch a maintainer
# loosening the anchor.
grep_line=$(grep -F "n_obj=" "${STAGE_SH}" | head -n 1 || true)
if ! printf '%s' "${grep_line}" | grep -qF "grep -c '^id:'"; then
    fail "stage_legacy_setup.sh:173" "n_obj grep is not anchored on '^id:' — production source drifted: '${grep_line}'"
fi
n_obj=$(grep -c '^id:' "${FIXTURES}/yubihsm-shell-list-objects.txt")
if [ "${n_obj}" != "4" ]; then
    fail "stage_legacy_setup.sh:173" "expected n_obj=4 (1 default-auth + 1 wrap + 1 app-auth + 1 R10-L2 foil), got ${n_obj}"
fi
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 2: stage_legacy_setup.sh:205-206 — wrap-key id extractor.
# =====================================================================
# Extract the awk program from production source by needle. If the
# program drifts back to a pre-R10-L2 substring shape (e.g.
# /^wrap-key,/ or /wrap-key/), the extracted program will yield a
# different value when run against the fixture and this block fails.
awk_prog_stage_wrap=$(extract_awk "${STAGE_SH}" '"wrap-key" {print $2; exit}')
if [ -z "${awk_prog_stage_wrap}" ]; then
    fail "stage_legacy_setup.sh:205-206" "could not extract wrap-key awk program from production source"
fi
# Anchor-check: the production awk MUST use a column-anchored predicate.
# Pre-R10-L2 substring forms (`/wrap-key/`, `/^wrap-key,/`) all lack the
# `$4 == "wrap-key"` shape — refuse to proceed if production drifted.
# shellcheck disable=SC2016  # `$4` is the literal awk-field reference we're searching for
if ! printf '%s' "${awk_prog_stage_wrap}" | grep -qF '$4 == "wrap-key"'; then
    fail "stage_legacy_setup.sh:205-206" "R10-L2 regression: production awk lost the column-anchored '\$4 == \"wrap-key\"' predicate; got: ${awk_prog_stage_wrap}"
fi
got_wrap_id=$(awk -F'[, ]+' "${awk_prog_stage_wrap}" \
              "${FIXTURES}/yubihsm-shell-list-objects.txt")
if [ "${got_wrap_id}" != "0xa5a2" ]; then
    fail "stage_legacy_setup.sh:205-206" "wrap-key extractor diverged from fixture; expected 0xa5a2, got '${got_wrap_id}' (awk: ${awk_prog_stage_wrap})"
fi
# Negative-grep: ensure the foil's id 0xDEAD was NOT captured.
if [ "${got_wrap_id}" = "0xDEAD" ] || [ "${got_wrap_id}" = "0xdead" ]; then
    fail "stage_legacy_setup.sh:205-206" "R10-L2 regression: wrap-key extractor captured foil auth-key id 0xDEAD"
fi
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 3: stage_legacy_setup.sh:208-209 — app auth-key id extractor.
# =====================================================================
# Same in-place extraction strategy.
awk_prog_stage_auth=$(extract_awk "${STAGE_SH}" '"authentication-key" && $2 != "0x0001"')
if [ -z "${awk_prog_stage_auth}" ]; then
    fail "stage_legacy_setup.sh:208-209" "could not extract auth-key awk program from production source"
fi
# shellcheck disable=SC2016  # `$4` is the literal awk-field reference we're searching for
if ! printf '%s' "${awk_prog_stage_auth}" | grep -qF '$4 == "authentication-key"'; then
    fail "stage_legacy_setup.sh:208-209" "R10-L2 regression: production auth-key awk lost the column-anchored predicate; got: ${awk_prog_stage_auth}"
fi
got_app_auth_id=$(awk -F'[, ]+' "${awk_prog_stage_auth}" \
                  "${FIXTURES}/yubihsm-shell-list-objects.txt")
if [ "${got_app_auth_id}" != "0xc995" ]; then
    fail "stage_legacy_setup.sh:208-209" "app-auth extractor diverged; expected 0xc995, got '${got_app_auth_id}' (awk: ${awk_prog_stage_auth})"
fi
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 4: _extract_shares.sh:12-15 — T-N-base64 share-line extractor.
# =====================================================================
# The production script IS the parser; run it directly against the
# fixture. If anyone reverts the sed/grep/awk pipeline back to a stub
# shape that doesn't strip ANSI escapes, this block fails (the fixture
# has real ANSI bytes interleaved).
SHARES_OUT=$(mktemp)
trap 'rm -f "${SHARES_OUT}"' EXIT INT TERM
# Tolerate non-zero exit from _extract_shares.sh: it exits 1 when zero
# candidates are kept (grep -oE returns 1 on no-match under pipefail).
# We want the parity test's explicit `[ "${n_shares}" != "3" ]` check to
# fire the FAIL banner rather than `set -e` aborting silently.
set +e
"${EXTRACT_SH}" "${FIXTURES}/yubihsm-setup-ksp.txt" > "${SHARES_OUT}" 2>/dev/null
extract_rc=$?
set -e
n_shares=$(wc -l < "${SHARES_OUT}")
if [ "${n_shares}" != "3" ]; then
    fail "_extract_shares.sh:12-15" "expected 3 shares (2-of-3 fixture), got ${n_shares} (extract rc=${extract_rc})"
fi
# Each output line must match the canonical share shape.
while IFS= read -r line; do
    if ! printf '%s' "${line}" | grep -qE '^[0-9]{1,2}-[0-9]{1,3}-[A-Za-z0-9+/]{70}$'; then
        fail "_extract_shares.sh:12-15" "non-canonical share line emitted: '${line}'"
    fi
done < "${SHARES_OUT}"
# Negative-grep: ensure the noise line 00-00-DDD... was REJECTED.
if grep -q '^00-' "${SHARES_OUT}"; then
    fail "_extract_shares.sh:12-15" "noise line 00-00-... leaked through bounds filter"
fi
# Positive-grep: ensure each expected share is present.
for prefix in "2-1-" "2-2-" "2-3-"; do
    if ! grep -q "^${prefix}" "${SHARES_OUT}"; then
        fail "_extract_shares.sh:12-15" "expected share prefix ${prefix} missing from extract"
    fi
done
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 5: verify_roundtrip.sh:69-71 — ALL_WRAP_IDS extractor + count.
# =====================================================================
# Locate the awk program in verify's source; the production code's awk
# is the lock-bearing predicate `$4 == "wrap-key"`. Same drift-detection.
awk_prog_verify_wrap=$(extract_awk "${VERIFY_SH}" '"wrap-key" {print $2}')
if [ -z "${awk_prog_verify_wrap}" ]; then
    fail "verify_roundtrip.sh:69-71" "could not extract wrap-key awk program from verify source"
fi
# shellcheck disable=SC2016  # `$4` is the literal awk-field reference we're searching for
if ! printf '%s' "${awk_prog_verify_wrap}" | grep -qF '$4 == "wrap-key"'; then
    fail "verify_roundtrip.sh:69-71" "R10-L2 regression: verify's wrap-key awk lost the column-anchored predicate; got: ${awk_prog_verify_wrap}"
fi
ALL_WRAP_IDS=$(awk -F'[, ]+' "${awk_prog_verify_wrap}" \
               "${FIXTURES}/yubihsm-shell-list-objects.txt" \
             | tr 'A-F' 'a-f')
N_WRAP=$(printf '%s\n' "${ALL_WRAP_IDS}" | awk 'NF{n++} END{print n+0}')
if [ "${N_WRAP}" != "1" ]; then
    fail "verify_roundtrip.sh:69-71" "expected exactly 1 wrap-key in fixture, got N_WRAP=${N_WRAP} (${ALL_WRAP_IDS})"
fi
if [ "${ALL_WRAP_IDS}" != "0xa5a2" ]; then
    fail "verify_roundtrip.sh:69-71" "ALL_WRAP_IDS extractor diverged; expected 0xa5a2, got '${ALL_WRAP_IDS}' (awk: ${awk_prog_verify_wrap})"
fi
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 6: verify_roundtrip.sh:96-104 — put-wrapped success/failure shape.
# =====================================================================
# The production code's "parser" here is the exit-code check on the
# put-wrapped invocation. We exercise both committed transcripts:
#   - put-wrapped-ok.txt MUST contain the success marker.
#   - put-wrapped-authfail.txt MUST contain the CCM/wrap-key failure
#     marker AND MUST NOT contain the success marker.
OK_LOG="${FIXTURES}/yubihsm-shell-put-wrapped-ok.txt"
FAIL_LOG="${FIXTURES}/yubihsm-shell-put-wrapped-authfail.txt"
if ! grep -q 'Object imported as' "${OK_LOG}"; then
    fail "verify_roundtrip.sh:96-104" "put-wrapped-ok fixture missing 'Object imported as' marker"
fi
if ! grep -qE 'Unable to import|Wrong CCM|invalid wrap-key' "${FAIL_LOG}"; then
    fail "verify_roundtrip.sh:96-104" "put-wrapped-authfail fixture missing CCM-failure marker"
fi
if grep -q 'Object imported as' "${FAIL_LOG}"; then
    fail "verify_roundtrip.sh:96-104" "put-wrapped-authfail fixture wrongly contains success marker"
fi
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 7: verify_roundtrip.sh:107 — get-public-key PEM shape.
# =====================================================================
# Production uses `diff -q` between two captures; no field extraction.
# We assert the PEM markers are present (a non-PEM blob would cause the
# downstream sha256 diff to silently succeed on two corrupt-but-equal
# files; verifying the format prevents that failure mode).
PEMTXT="${FIXTURES}/yubihsm-shell-get-public-key.txt"
if ! grep -q -- '-----BEGIN PUBLIC KEY-----' "${PEMTXT}"; then
    fail "verify_roundtrip.sh:107" "get-public-key fixture missing PEM BEGIN marker"
fi
if ! grep -q -- '-----END PUBLIC KEY-----' "${PEMTXT}"; then
    fail "verify_roundtrip.sh:107" "get-public-key fixture missing PEM END marker"
fi
PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# =====================================================================
# Parser 8: drive_manager.py:361..:474 — pexpect TUI prompt regexes.
# =====================================================================
# For each p.expect()/p.expect_exact() pattern in drive_manager.py,
# verify the pattern matches at least one line in the prompts fixture.
# We extract patterns BY READING the production file (not by hardcoding
# them inline) so a parser drift surfaces here. The extraction grep is
# permissive: any line containing `p.expect(` or `p.expect_exact(` is
# inspected, then the literal pattern between `r"..."` (or `"..."`) is
# pulled out via sed.
PROMPTS="${FIXTURES}/yubihsm-manager-tui-prompts.txt"

# Helper that extracts the pattern from a p.expect or p.expect_exact
# line by needle. Filters to lines containing `p.expect(` first so that
# matching COMMENTS (which often quote the prompt text) do not poison
# the extraction.
extract_pyexpect() {
    local needle="$1"
    # Tolerate "needle not found" — see extract_awk for rationale.
    { grep -F 'p.expect' "${DRIVER_PY}" | grep -F -- "${needle}" || true; } \
        | head -n 1 \
        | sed -E 's/.*p\.expect(_exact)?\((r?)"([^"]*)"[^)]*\).*/\3/'
}

# drive_manager.py:361 — wrap-menu anchor.
pat1=$(extract_pyexpect 'all wrap keys stored on the YubiHSM')
[ -n "${pat1}" ] || fail "drive_manager.py:361" "could not extract p.expect pattern from production"
grep -qE -- "${pat1}" "${PROMPTS}" \
    || fail "drive_manager.py:361" "extracted production regex did not match any prompt-fixture line: ${pat1}"

# drive_manager.py:416 — expect_exact "Re-create from shares?".
pat2=$(extract_pyexpect 'Re-create from shares?')
[ -n "${pat2}" ] || fail "drive_manager.py:416" "could not extract p.expect_exact pattern from production"
grep -qF -- "${pat2}" "${PROMPTS}" \
    || fail "drive_manager.py:416" "extracted literal '${pat2}' missing from prompt fixture"

# drive_manager.py:429 — Press-any-key recreate prompt.
pat3=$(extract_pyexpect 'Press any key to recreate wrap key from shares')
[ -n "${pat3}" ] || fail "drive_manager.py:429" "could not extract p.expect pattern from production"
grep -qE -- "${pat3}" "${PROMPTS}" \
    || fail "drive_manager.py:429" "extracted regex did not match: ${pat3}"

# drive_manager.py:433 — share-count prompt.
pat4=$(extract_pyexpect 'Enter the number of shares to re-create the AES wrap key')
[ -n "${pat4}" ] || fail "drive_manager.py:433" "could not extract p.expect pattern from production"
grep -qE -- "${pat4}" "${PROMPTS}" \
    || fail "drive_manager.py:433" "extracted regex did not match: ${pat4}"

# drive_manager.py:438 — per-share entry prompt. Production uses an
# f-string `rf"Enter share number {i}"`; the extraction grep needs to
# match the production-line shape minus the f-prefix. Test for i=1.
grep -qF 'p.expect(rf"Enter share number {i}' "${DRIVER_PY}" \
    || fail "drive_manager.py:438" "share-entry f-string pattern drifted in production"
grep -qE 'Enter share number 1' "${PROMPTS}" \
    || fail "drive_manager.py:438" "fixture missing 'Enter share number 1' line"

# drive_manager.py:454 — object-label prompt.
pat6=$(extract_pyexpect 'Enter object label')
[ -n "${pat6}" ] || fail "drive_manager.py:454" "could not extract p.expect pattern from production"
grep -qE -- "${pat6}" "${PROMPTS}" \
    || fail "drive_manager.py:454" "extracted regex did not match: ${pat6}"

# drive_manager.py:459 — metadata-confirmation prompt.
pat7=$(extract_pyexpect 'Import wrap key with')
[ -n "${pat7}" ] || fail "drive_manager.py:459" "could not extract p.expect pattern from production"
grep -qE -- "${pat7}" "${PROMPTS}" \
    || fail "drive_manager.py:459" "extracted regex did not match: ${pat7}"

# drive_manager.py:474 — case-insensitive "Imported wrap key with ID".
# Production uses Python's \s which grep -E does not accept; verify
# the bracket-class prefix is intact (this is the lock-bearing case-
# insensitive shape that handles a pre-release that capitalised "Imported")
# and that the success line in the fixture starts with the case-correct shape.
grep -qF '[Ii]mported wrap key with [Ii][Dd][:' "${DRIVER_PY}" \
    || fail "drive_manager.py:474" "case-insensitive Imported regex drifted in production"
grep -qE '[Ii]mported wrap key with [Ii][Dd][:[:space:]=]' "${PROMPTS}" \
    || fail "drive_manager.py:474" "fixture missing 'Imported wrap key with ID' success line"

# drive_manager.py:479 — id-capture regex against the same line.
grep -qF '(0x[0-9a-fA-F]{1,4})' "${DRIVER_PY}" \
    || fail "drive_manager.py:479" "id-capture regex drifted in production"
grep -qE 'Imported wrap key with ID 0x[0-9a-fA-F]{1,4}' "${PROMPTS}" \
    || fail "drive_manager.py:479" "fixture success line is not id-capturable"

PARSERS_VERIFIED=$((PARSERS_VERIFIED + 1))

# Track fixtures used (one per .txt file). Use find (not ls) per shellcheck SC2012.
TRANSCRIPTS_USED=$(find "${FIXTURES}" -maxdepth 1 -name '*.txt' -type f | wc -l)

echo "PASS: test_transcript_parity.sh (${PARSERS_VERIFIED} parser sites verified against ${TRANSCRIPTS_USED} transcripts)"
