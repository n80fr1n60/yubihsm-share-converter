#!/usr/bin/env bash
# Test for E-M2: stage_legacy_setup.sh must reject an unsafe OUT_DIR up front
# with exit 8 + an explanatory stderr message. Four scenarios:
#
#   1. Symlinked OUT_DIR — same-uid attacker could pre-plant a symlink
#      pointing at a world-readable location; stage must refuse with exit 8
#      and stderr containing "OUT_DIR is a symlink".
#   2. Wrong-uid OUT_DIR — pre-created directory owned by a different uid.
#      Requires root to fake (chown to a different uid); skip cleanly when
#      running as non-root and rely on the implementation's `stat -c '%u'`
#      vs `id -u` comparison being trivially correct.
#   3. Wrong-mode OUT_DIR — pre-created directory mode 0755; stage must
#      refuse with exit 8 and stderr containing "OUT_DIR is not mode 0700".
#   4. Happy path — owned-by-current-uid mode-0700 real directory. The
#      E-M2 hygiene gate must NOT fire. The script will then fail later
#      at the missing-yubihsm-shell / not-at-factory-state step (different
#      exit code), but the E-M2 refusal-banner text ("refusing") must NOT
#      appear in stderr.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
STAGE="$SCRIPT_DIR/../stage_legacy_setup.sh"
[ -x "$STAGE" ] || { echo "FAIL: $STAGE not executable" >&2; exit 1; }

TMPROOT=$(mktemp -d)
trap 'rm -rf "$TMPROOT"' EXIT

pass_count=0
skip_count=0

# ---- Scenario 1: symlink rejected --------------------------------------
S1_REAL="$TMPROOT/s1_real"
S1_LINK="$TMPROOT/s1_symlink_out"
mkdir -m 0700 "$S1_REAL"
ln -sf "$S1_REAL" "$S1_LINK"

set +e
OUT_DIR="$S1_LINK" bash "$STAGE" > "$TMPROOT/s1.stdout" 2> "$TMPROOT/s1.stderr"
s1_rc=$?
set -e

if [ "$s1_rc" != "8" ]; then
    echo "FAIL[s1]: expected exit 8 for symlinked OUT_DIR, got $s1_rc" >&2
    echo "--- s1 stderr ---" >&2; cat "$TMPROOT/s1.stderr" >&2
    exit 1
fi
if ! grep -q "OUT_DIR is a symlink" "$TMPROOT/s1.stderr"; then
    echo "FAIL[s1]: stderr did not contain 'OUT_DIR is a symlink'" >&2
    cat "$TMPROOT/s1.stderr" >&2
    exit 1
fi
echo "PASS[s1]: symlinked OUT_DIR rejected with exit 8"
pass_count=$((pass_count + 1))

# ---- Scenario 2: wrong-uid rejected (root-only; skip as non-root) ------
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "SKIP[s2]: cannot fake non-self uid as non-root; the implementation's"
    echo "          stat -c '%u' vs id -u comparison is trivially correct."
    skip_count=$((skip_count + 1))
else
    # Best-effort: pick uid 65534 (nobody on most distros) for the chown.
    S2_DIR="$TMPROOT/s2_wronguid"
    mkdir -m 0700 "$S2_DIR"
    chown 65534 "$S2_DIR"
    set +e
    OUT_DIR="$S2_DIR" bash "$STAGE" > "$TMPROOT/s2.stdout" 2> "$TMPROOT/s2.stderr"
    s2_rc=$?
    set -e
    if [ "$s2_rc" != "8" ]; then
        echo "FAIL[s2]: expected exit 8 for wrong-uid OUT_DIR, got $s2_rc" >&2
        cat "$TMPROOT/s2.stderr" >&2
        exit 1
    fi
    if ! grep -q "is not owned by uid" "$TMPROOT/s2.stderr"; then
        echo "FAIL[s2]: stderr did not contain 'is not owned by uid'" >&2
        cat "$TMPROOT/s2.stderr" >&2
        exit 1
    fi
    echo "PASS[s2]: wrong-uid OUT_DIR rejected with exit 8"
    pass_count=$((pass_count + 1))
fi

# ---- Scenario 3: wrong-mode rejected -----------------------------------
S3_DIR="$TMPROOT/s3_wrongmode"
mkdir -m 0755 "$S3_DIR"

set +e
OUT_DIR="$S3_DIR" bash "$STAGE" > "$TMPROOT/s3.stdout" 2> "$TMPROOT/s3.stderr"
s3_rc=$?
set -e

if [ "$s3_rc" != "8" ]; then
    echo "FAIL[s3]: expected exit 8 for wrong-mode (0755) OUT_DIR, got $s3_rc" >&2
    echo "--- s3 stderr ---" >&2; cat "$TMPROOT/s3.stderr" >&2
    exit 1
fi
if ! grep -q "OUT_DIR is not mode 0700" "$TMPROOT/s3.stderr"; then
    echo "FAIL[s3]: stderr did not contain 'OUT_DIR is not mode 0700'" >&2
    cat "$TMPROOT/s3.stderr" >&2
    exit 1
fi
echo "PASS[s3]: wrong-mode (0755) OUT_DIR rejected with exit 8"
pass_count=$((pass_count + 1))

# ---- Scenario 4: happy path — E-M2 gate doesn't fire -------------------
# Owned-by-current-uid, mode-0700 directory. The script proceeds past the
# E-M2 hygiene gate; it will fail later at the HSM-not-at-factory-state /
# missing-tool / connector-unreachable step. We assert that:
#   (a) the exit code is NOT 8, AND
#   (b) stderr does NOT contain the "refusing" token (which appears only
#       in the E-M2 error banners).
S4_DIR="$TMPROOT/s4_happy"
mkdir -m 0700 "$S4_DIR"

set +e
OUT_DIR="$S4_DIR" bash "$STAGE" > "$TMPROOT/s4.stdout" 2> "$TMPROOT/s4.stderr"
s4_rc=$?
set -e

if [ "$s4_rc" = "8" ]; then
    echo "FAIL[s4]: happy-path OUT_DIR triggered exit 8 (E-M2 gate fired)" >&2
    echo "--- s4 stderr ---" >&2; cat "$TMPROOT/s4.stderr" >&2
    exit 1
fi
if grep -q "refusing" "$TMPROOT/s4.stderr"; then
    echo "FAIL[s4]: stderr contained 'refusing' — E-M2 gate fired on a good dir" >&2
    cat "$TMPROOT/s4.stderr" >&2
    exit 1
fi
echo "PASS[s4]: happy-path OUT_DIR passed the E-M2 gate (rc=$s4_rc, non-8)"
pass_count=$((pass_count + 1))

echo "test_stage_out_dir_hygiene.sh: $pass_count passed, $skip_count skipped"
