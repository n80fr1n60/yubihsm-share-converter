#!/usr/bin/env bash
# Test for H-3-3: verify_roundtrip.sh must hard-fail with exit 5 when
# OUT_DIR is unset, and emit a stderr banner explaining why (so an
# operator who lost the export across a sub-shell sees an actionable
# message instead of silently consuming a stale /tmp/imported_wrap_id.txt
# from a prior ceremony).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VERIFY="$SCRIPT_DIR/../verify_roundtrip.sh"
[ -x "$VERIFY" ] || { echo "FAIL: $VERIFY not executable" >&2; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Run with OUT_DIR explicitly unset. Use `env -u OUT_DIR` so an inherited
# OUT_DIR from the test harness can't pollute the assertion. We do NOT
# stub yubihsm-shell — verify must exit at the OUT_DIR check BEFORE
# command -v runs.
set +e
env -u OUT_DIR bash "$VERIFY" > "$TMPDIR/stdout.log" 2> "$TMPDIR/stderr.log"
rc=$?
set -e

if [ "$rc" != "5" ]; then
    echo "FAIL: expected rc=5, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$TMPDIR/stdout.log" >&2
    echo "--- stderr ---" >&2; cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

if ! grep -q "OUT_DIR is unset" "$TMPDIR/stderr.log"; then
    echo "FAIL: stderr did not contain 'OUT_DIR is unset' banner" >&2
    cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

if ! grep -q "Refusing to default to /tmp" "$TMPDIR/stderr.log"; then
    echo "FAIL: stderr did not contain 'Refusing to default to /tmp' rationale" >&2
    cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

echo "PASS: test_verify_out_dir_unset.sh (rc=5; banner emitted)"
