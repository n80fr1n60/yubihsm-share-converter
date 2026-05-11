#!/usr/bin/env bash
# Test for H-Sc1: scripts/_extract_shares.sh handles >9-share ceremonies,
# strips ANSI escapes, and rejects garbage matches (threshold/index 0).
#
# Synthesises a raw log with thresholds 2..12 and indices 1..12 plus
# ANSI noise plus a transient noise line `00-00-<70 base64 chars>`.
# Asserts: exactly 6 lines extracted, `11-12-` is present, `00-00-` is NOT.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
EXTRACT="$SCRIPT_DIR/../_extract_shares.sh"
[ -x "$EXTRACT" ] || { echo "FAIL: $EXTRACT not executable" >&2; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
RAW="$TMPDIR/raw.log"
OUT="$TMPDIR/legacy.txt"

# 70-char base64 payload (a single recognised char, repeated).
B70=$(printf 'A%.0s' $(seq 1 70))
B70_X=$(printf 'B%.0s' $(seq 1 70))
B70_Y=$(printf 'C%.0s' $(seq 1 70))
B70_Z=$(printf 'D%.0s' $(seq 1 70))
B70_W=$(printf 'E%.0s' $(seq 1 70))
B70_V=$(printf 'F%.0s' $(seq 1 70))
B70_N=$(printf 'G%.0s' $(seq 1 70))

# ANSI escape (CSI Reset) we want stripped before grep.
ESC=$(printf '\033')

# Build a raw log with mixed thresholds (2..12) and indices (1..12) — only
# the 6 share lines below should make it through:
#   2-1-  3-3-  9-9-  10-10-  11-11-  11-12-
# Plus a transient noise line `00-00-…` (matches the regex shape but
# fails the awk sanity filter) and some unrelated yubihsm-setup chatter.
# Note: yubihsm-setup writes shares either at start-of-line or after a
# space — never after a tab. The bracket class `[ \t]` is a GNU-grep
# literal-string and `\t` does NOT expand to TAB inside `[...]`; that
# matches real-world stdout and is what architect H-8 prescribes.
cat > "$RAW" <<EOF
${ESC}[1;33mWelcome to yubihsm-setup${ESC}[0m
[setup] generating shares...
2-1-${B70}
${ESC}[2K[setup] share recorded
3-3-${B70_X}
9-9-${B70_Y}
[setup] 10-10-${B70_Z}
 11-11-${B70_W}
11-12-${B70_V}
[setup] noise: 00-00-${B70_N}
[setup] done.
EOF

"$EXTRACT" "$RAW" > "$OUT" 2>"$TMPDIR/stderr.log"

n=$(wc -l < "$OUT")
if [ "$n" != "6" ]; then
    echo "FAIL: expected 6 lines extracted, got $n" >&2
    echo "--- output ---" >&2
    cat "$OUT" >&2
    echo "--- stderr ---" >&2
    cat "$TMPDIR/stderr.log" >&2
    exit 1
fi

if ! grep -q "^11-12-" "$OUT"; then
    echo "FAIL: 11-12- (>9 ceremony share) not present in output" >&2
    cat "$OUT" >&2
    exit 1
fi

if grep -q "^00-00-" "$OUT"; then
    echo "FAIL: noise line 00-00- leaked into output" >&2
    cat "$OUT" >&2
    exit 1
fi

# Spot-check each expected share is present
for prefix in "2-1-" "3-3-" "9-9-" "10-10-" "11-11-" "11-12-"; do
    if ! grep -q "^${prefix}" "$OUT"; then
        echo "FAIL: expected share ${prefix} not in output" >&2
        cat "$OUT" >&2
        exit 1
    fi
done

echo "PASS: test_stage_extraction.sh (6 shares extracted; 11-12- present; 00-00- rejected)"
