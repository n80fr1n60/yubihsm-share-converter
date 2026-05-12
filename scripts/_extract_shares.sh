#!/usr/bin/env bash
# Extract legacy yubihsm-setup share lines (T-N-base64{70}) from a raw
# captured log. Strips ANSI escapes, tolerates surrounding spaces/tabs
# (NOT newlines — see architect H-8: `[ \t]` not `[[:space:]]`), and
# drops out-of-range candidates (threshold or index 0, threshold > 31,
# index > 255) BEFORE writing so transient log lines that happen to
# match the regex can't masquerade as real shares.
#
# Usage: _extract_shares.sh <raw-log-path>  > <legacy-shares-out>
#
# R12-02 parity gate: the sed/grep/awk pipeline below is exercised
# against tests/fixtures/device-transcripts/yubihsm-setup-ksp.txt via
# scripts/tests/test_transcript_parity.sh ("Parser 4" block).
set -euo pipefail
RAW=$1
sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$RAW" \
    | grep -oE '(^|[ \t])[0-9]{1,2}-[0-9]{1,3}-[a-zA-Z0-9+/]{70}($|[ \t])' \
    | tr -d ' \t' \
    | awk -F'-' '$1 != "0" && $2 != "0" && $1+0 >= 2 && $1+0 <= 31 && $2+0 >= 1 && $2+0 <= 255 { print; kept++ }
                 END { if (kept == 0) print "extract: 0 candidates kept" > "/dev/stderr" }'
