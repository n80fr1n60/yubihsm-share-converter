#!/usr/bin/env bash
# Test for H-3-2: verify_roundtrip.sh's wrap-id compare must lowercase BOTH
# producers (the recorded `imported_wrap_id.txt` and the `list-objects` output)
# before equality. A future SDK ever printing uppercase `0xABCD` on either
# side would otherwise fire exit 8 spuriously even though the wrap-key bytes
# are byte-for-byte correct.
#
# Six fixture combinations (lower/lower, upper/lower, lower/upper,
# upper/upper, real-mismatch, substring-in-label foil — R10-L2 guard):
#   1. recorded=0xabcd  list-objects=0xabcd  → exit 0 (id compare passes;
#                                              put-wrapped stub then exits 9)
#   2. recorded=0xABCD  list-objects=0xabcd  → exit 0
#   3. recorded=0xabcd  list-objects=0xABCD  → exit 0
#   4. recorded=0xABCD  list-objects=0xABCD  → exit 0
#   5. recorded=0xabcd  list-objects=0xdead  → exit 8
#   6. R10-L2 foil: an authentication-key row with label `my-wrap-key-label`
#                   PLUS a genuine wrap-key row. The post-R10-L2
#                   column-anchored awk regex `/^wrap-key,/` must extract
#                   ONLY the genuine wrap-key id, NOT the foil's auth-key
#                   id (pre-fix `/wrap-key/` substring match would have
#                   captured BOTH, fired N_WRAP=2 → exit 7). The toggle is
#                   the env var YHSM_EMIT_FOIL_LABEL=1 which prepends a
#                   foil authentication-key row to the stub's output.
#
# Strategy: stub `yubihsm-shell` so `list-objects` prints exactly one
# `wrap-key, <id>, …` row and an authentication-key (the existing factory-
# state assertion at stage time isn't relevant here — verify only counts
# wrap-keys). Stub `put-wrapped` to fail loudly so we never need a real HSM.
# The pass-cases stop AT put-wrapped (exit 9 — H-V2 banner); the mismatch
# case exits 8 (H-3-2 / H-V1) BEFORE put-wrapped is invoked.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VERIFY="$SCRIPT_DIR/../verify_roundtrip.sh"
[ -x "$VERIFY" ] || { echo "FAIL: $VERIFY not executable" >&2; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Pre-create the artefacts verify_roundtrip.sh demands exist on disk before
# even reaching the id-compare block (early-return paths use exits 4/6).
: > "$TMPDIR/wrapped_victim.bin"
: > "$TMPDIR/victim_pubkey.pem"

# Stub directory placed first on PATH. We override yubihsm-shell so verify
# never touches a real HSM. The stub's behaviour is parameterised through
# the env-var YHSM_LIST_WRAP_ID at invocation time.
STUB_DIR="$TMPDIR/stubs"
mkdir -p "$STUB_DIR"

cat > "$STUB_DIR/yubihsm-shell" <<'STUB'
#!/usr/bin/env bash
# Minimal yubihsm-shell stub for H-3-2 test.
#
# Recognised arg patterns:
#   ... -a list-objects   → print one row whose column-anchored `wrap-key,`
#                            prefix lets verify's `awk -F'[, ]+'
#                            '/^wrap-key,/ {print $2}'` extract the id at
#                            field 2 (R10-L2 tightened the awk from
#                            substring `/wrap-key/` to regex-anchored
#                            `/^wrap-key,/`). Format mirrors the real
#                            yubihsm-shell output: `wrap-key, <id>, …`.
#                            Also emit an authentication-key row that does
#                            NOT match /^wrap-key,/ so verify's exactly-one
#                            assertion (N_WRAP=1) passes.
#                            If YHSM_EMIT_FOIL_LABEL=1, ALSO prepend a
#                            second authentication-key row whose label
#                            contains the substring "wrap-key" — the
#                            R10-L2 regression guard: post-fix awk must
#                            ignore it, pre-fix awk would have matched it.
#   ... -a put-wrapped …  → exit non-zero so verify reaches the H-V2
#                            FAILED banner (exit 9). The H-3-2 test
#                            doesn't care about put-wrapped success —
#                            only the BEFORE-put-wrapped id-compare path.
#   anything else         → exit 0 silently.
for arg in "$@"; do
    if [ "$arg" = "list-objects" ]; then
        printf 'authentication-key, 0x0001, sequence: 0\n'
        if [ "${YHSM_EMIT_FOIL_LABEL:-0}" = "1" ]; then
            # R10-L2 foil: auth-key row with label that CONTAINS the
            # substring "wrap-key". Pre-fix awk `/wrap-key/` would match
            # this row and emit `0xDEAD` (the auth-key id) alongside the
            # genuine wrap-key id, blowing N_WRAP to 2 → exit 7.
            # Post-fix awk `/^wrap-key,/` ignores this row because it
            # starts with "authentication-key,", not "wrap-key,".
            printf 'authentication-key, 0xDEAD, sequence: 0, label: my-wrap-key-label\n'
        fi
        printf 'wrap-key, %s, sequence: 0\n' "$YHSM_LIST_WRAP_ID"
        exit 0
    fi
    if [ "$arg" = "put-wrapped" ]; then
        echo "stub put-wrapped: deliberate failure (H-3-2 test stops here)" >&2
        exit 1
    fi
done
exit 0
STUB
chmod +x "$STUB_DIR/yubihsm-shell"

run_case() {
    local name="$1" recorded="$2" list_id="$3" expected_rc="$4"
    # 5th positional arg (optional): emit_foil — 1 enables the R10-L2 foil
    # authentication-key row in the stub. Default 0 (legacy 5-case behaviour).
    local emit_foil="${5:-0}"
    rm -f "$TMPDIR/imported_wrap_id.txt"
    printf '%s\n' "$recorded" > "$TMPDIR/imported_wrap_id.txt"

    set +e
    YHSM_LIST_WRAP_ID="$list_id" \
        YHSM_EMIT_FOIL_LABEL="$emit_foil" \
        OUT_DIR="$TMPDIR" \
        PATH="$STUB_DIR:$PATH" \
        bash "$VERIFY" > "$TMPDIR/stdout.log" 2> "$TMPDIR/stderr.log"
    local rc=$?
    set -e

    if [ "$rc" != "$expected_rc" ]; then
        echo "FAIL [$name]: expected rc=$expected_rc, got rc=$rc" >&2
        echo "  recorded=$recorded list_id=$list_id emit_foil=$emit_foil" >&2
        echo "--- stdout ---" >&2; cat "$TMPDIR/stdout.log" >&2
        echo "--- stderr ---" >&2; cat "$TMPDIR/stderr.log" >&2
        exit 1
    fi
}

assert_stderr_contains() {
    local name="$1" needle="$2"
    if ! grep -qF -- "$needle" "$TMPDIR/stderr.log"; then
        echo "FAIL [$name]: stderr missing expected fragment: $needle" >&2
        cat "$TMPDIR/stderr.log" >&2
        exit 1
    fi
}

# Cases 1–4: id-compare passes; verify proceeds to put-wrapped which the stub
# fails → exit 9 (H-V2 FAILED banner). The H-3-2 success criterion is that
# we did NOT exit 8 on case-only differences.
run_case "lower/lower" "0xabcd" "0xabcd" 9
run_case "upper/lower" "0xABCD" "0xabcd" 9
run_case "lower/upper" "0xabcd" "0xABCD" 9
run_case "upper/upper" "0xABCD" "0xABCD" 9

# Case 5: real value mismatch. Must exit 8 BEFORE put-wrapped runs, AND
# the stderr banner must include the unambiguous "real mismatch, not a
# case-only difference" reassurance line.
run_case "real-mismatch" "0xabcd" "0xdead" 8
# v2 (arch new): H-3-2 stderr now spans two echoed lines. Match either —
# the second-line reassurance is the load-bearing one for the operator.
assert_stderr_contains "real-mismatch" "this is a real mismatch, not a case-only difference"

# Case 6 (R10-L2): substring-in-label foil regression guard.
# The stub emits TWO rows: (a) a foil authentication-key whose LABEL contains
# the substring "wrap-key" (label: my-wrap-key-label), and (b) a genuine
# wrap-key row. Pre-R10-L2 awk `/wrap-key/` would have matched BOTH rows,
# capturing the foil's auth-key id (0xDEAD) alongside the genuine wrap-key
# id, blowing N_WRAP to 2 and firing exit 7. Post-R10-L2 awk `/^wrap-key,/`
# matches ONLY the genuine wrap-key row, so verify reaches the id-compare
# (passes — recorded == list-objects == 0xabcd) and proceeds to the
# put-wrapped stub (which deliberately fails → exit 9).
run_case "foil-label" "0xabcd" "0xabcd" 9 1
# Negative-grep: stderr must NOT mention the foil's auth-key id 0xDEAD —
# proving the awk filter rejected the foil row entirely (not just dropped
# it from the count).
if grep -qFi -- "0xdead" "$TMPDIR/stderr.log"; then
    echo "FAIL [foil-label]: stderr leaked the foil auth-key id (0xDEAD) — awk did not reject the foil row" >&2
    cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

echo "PASS: test_verify_id_case.sh (6 cases — 4 case-only pairs accepted, 1 real mismatch rejected with reassurance line, 1 substring-in-label foil rejected by column-anchored awk)"
