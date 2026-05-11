#!/usr/bin/env bash
# Test for H-Sc2: when a delete-object fails during rollback, the EXIT
# trap must (a) emit "ROLLBACK FAILED" to stderr listing the orphans, and
# (b) terminate with exit code 6 (architect C-1 — `return 6` from an EXIT
# trap does NOT change the script's exit status; cleanup must `exit 6`).
#
# Strategy: the stage script aborts on missing prereqs (`yubihsm-shell`),
# so we can't just run it as-is. Instead we extract the cleanup() body
# from scripts/stage_legacy_setup.sh, paste it into a synthesised test
# harness that stubs `shell()` to fail, sets a non-empty CREATED_WRAP_ID,
# and triggers a non-zero exit so the EXIT trap fires the failure branch.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
STAGE="$SCRIPT_DIR/../stage_legacy_setup.sh"
[ -r "$STAGE" ] || { echo "FAIL: $STAGE not readable" >&2; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
HARNESS="$TMPDIR/harness.sh"

# Lift the cleanup() function definition (start `cleanup() {` line through
# the matching closing brace at column 0) out of the stage script verbatim.
awk '
    /^cleanup\(\) \{/ { in_fn=1 }
    in_fn { print }
    in_fn && /^\}/    { exit }
' "$STAGE" > "$TMPDIR/cleanup_fn.sh"

# Sanity-check the extraction.
grep -q "^cleanup() {"            "$TMPDIR/cleanup_fn.sh" || { echo "FAIL: cleanup() not extracted" >&2; cat "$TMPDIR/cleanup_fn.sh" >&2; exit 1; }
grep -q "ROLLBACK FAILED"         "$TMPDIR/cleanup_fn.sh" || { echo "FAIL: ROLLBACK FAILED branch not present in extracted cleanup()" >&2; exit 1; }
grep -qE "^[[:space:]]+exit 6$"   "$TMPDIR/cleanup_fn.sh" || { echo "FAIL: 'exit 6' path not present in extracted cleanup()" >&2; exit 1; }

cat > "$HARNESS" <<'OUTER'
#!/usr/bin/env bash
set -uo pipefail

# Stubs the cleanup function depends on.
CREATED_VICTIM_ID=""
CREATED_APP_AUTH_ID=""
CREATED_WRAP_ID="0xdead"
RAW=""

# Stub `shell` to always fail — every delete-object will be recorded as
# an rb_failure entry.
shell() { return 1; }

OUTER
cat "$TMPDIR/cleanup_fn.sh" >> "$HARNESS"
cat >> "$HARNESS" <<'OUTER'

# Trigger the EXIT trap with a non-zero exit status so cleanup() takes
# the failure branch. We need to set $? to non-zero just before cleanup
# runs. Easiest: invoke cleanup directly with an explicit fake rc.
# But cleanup's `local rc=$?` reads the LAST command's status; so we
# arrange that before calling.
trap cleanup EXIT
( exit 7 )    # makes $? = 7 just before the script exits.
OUTER

set +e
bash "$HARNESS" > "$TMPDIR/stdout.log" 2> "$TMPDIR/stderr.log"
ec=$?
set -e

if [ "$ec" != "6" ]; then
    echo "FAIL: expected exit code 6, got $ec" >&2
    echo "--- stdout ---" >&2; cat "$TMPDIR/stdout.log" >&2
    echo "--- stderr ---" >&2; cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

if ! grep -q "ROLLBACK FAILED" "$TMPDIR/stderr.log"; then
    echo "FAIL: stderr did not contain 'ROLLBACK FAILED'" >&2
    cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

if ! grep -q "wrap:0xdead" "$TMPDIR/stderr.log"; then
    echo "FAIL: stderr did not list the orphaned wrap-key id" >&2
    cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

echo "PASS: test_cleanup_partial_rollback.sh (exit=6; stderr contains ROLLBACK FAILED for wrap:0xdead)"
