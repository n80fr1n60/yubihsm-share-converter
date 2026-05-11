#!/usr/bin/env bash
# Final byte-equality test for the converter end-to-end run.
#
# Pre-condition: the manager has just imported the wrap-key from the
# converted shares (drive_manager.py succeeded). The HSM should have:
#   * default auth-key 0x0001
#   * the re-imported wrap-key (id matches the one captured in
#     ${OUT_DIR}/legacy_setup_raw.log; we re-discover it from list-objects)
#
# This script:
#   1. Calls put-wrapped on the saved blob using the manager-imported
#      wrap-key. AES-CCM is authenticated, so a single bit-flip in the
#      key bytes would cause this to fail.
#   2. Re-exports the recovered asymmetric key's public key and
#      diffs it against the snapshot taken before deletion.
#   3. Exits 0 on a clean match (proving byte-for-byte wrap-key
#      equality), nonzero on any mismatch / failure.
#
# Env: CON, AUTHKEY, PASSWORD, OUT_DIR — same defaults as stage script.

set -euo pipefail

CON=${CON:-http://127.0.0.1:12345}
AUTHKEY=${AUTHKEY:-1}
PASSWORD=${PASSWORD:-password}
# H-3-3: refuse to default OUT_DIR. A stale id-file or wrapped blob from a
# prior ceremony silently consumed by this run would defeat the byte-for-byte
# wrap-key equality check this script exists to perform. Hard-fail so the
# operator picks an explicit (preferably tmpfs) path. Exit 5 is unused
# elsewhere in this script (existing codes: 3/4/6/7/8/9 + 1).
if [ -z "${OUT_DIR:-}" ]; then
    echo "[verify] OUT_DIR is unset. Refusing to default to /tmp — stale" >&2
    echo "         id-file or wrapped blob from prior ceremony could be" >&2
    echo "         silently consumed. Set OUT_DIR and re-run." >&2
    exit 5
fi

WRAPPED=${OUT_DIR}/wrapped_victim.bin
PUBKEY=${OUT_DIR}/victim_pubkey.pem
PUBKEY_AFTER=${OUT_DIR}/victim_pubkey_final.pem

shell()  { yubihsm-shell --connector "$CON" -p "$PASSWORD" --authkey "$AUTHKEY" "$@"; }

command -v yubihsm-shell >/dev/null || { echo "[verify] missing yubihsm-shell" >&2; exit 3; }
[ -r "$WRAPPED" ] || { echo "[verify] missing $WRAPPED — did stage_legacy_setup.sh run?" >&2; exit 4; }
[ -r "$PUBKEY"  ] || { echo "[verify] missing $PUBKEY  — did stage_legacy_setup.sh run?" >&2; exit 4; }

# H-V1: three-layer wrap-id check — (1) read the id-file the driver wrote
# atomically at mode 0600, (2) assert exactly one wrap-key on the HSM,
# (3) assert that id matches the recorded one. Replaces the prior
# `awk '… {print $2; exit}'` first-match heuristic which would silently
# pick a stale wrap-key from a previous run and let put-wrapped fail with
# an opaque AES-CCM auth error. New exit codes 6/7/8 are distinct from
# the existing 3/4/5.
EXPECTED_FILE=${OUT_DIR}/imported_wrap_id.txt
if [ ! -r "$EXPECTED_FILE" ]; then
    echo "[verify] missing $EXPECTED_FILE — drive_manager did not record" >&2
    exit 6
fi
# H-3-2: normalise BOTH producers to lowercase BEFORE compare. A future SDK
# release printing uppercase `0xABCD` on either side (the recorded id-file or
# `list-objects` output) would otherwise fire exit 8 spuriously even though
# the wrap-key bytes are correct. Two `tr 'A-F' 'a-f'` insertions; the
# downstream compare is case-insensitive but the failure message still shows
# the (now-lowercased) ids verbatim, with an explicit reassurance line so an
# operator can't dismiss the mismatch as a case-only difference.
EXPECTED_WRAP_ID=$(tr -d '[:space:]' < "$EXPECTED_FILE" | tr 'A-F' 'a-f')

ALL_WRAP_IDS=$(shell -a list-objects 2>/dev/null \
    | awk -F'[, ]+' '/^wrap-key,/ {print $2}' \
    | tr 'A-F' 'a-f')
# v2 fix: `grep -c .` returns exit 1 on zero matches; under `set -euo pipefail`
# that aborts the script with rc=1 BEFORE the explicit `exit 7` below can fire.
# Use awk (always exits 0) to count non-empty lines so the zero-wrap-keys path
# correctly reaches the dedicated `exit 7` banner.
N_WRAP=$(printf '%s\n' "$ALL_WRAP_IDS" | awk 'NF{n++} END{print n+0}')
if [ "$N_WRAP" != "1" ]; then
    echo "[verify] expected 1 wrap-key, found $N_WRAP: $ALL_WRAP_IDS" >&2
    exit 7
fi
WRAP_ID="$ALL_WRAP_IDS"
if [ "$WRAP_ID" != "$EXPECTED_WRAP_ID" ]; then
    # v2 (sec L2): make the error wording unambiguous — both sides have
    # already been lowercased above, so this is a real value mismatch, not
    # a case-only difference an operator might dismiss.
    echo "[verify] wrap-key $WRAP_ID != recorded $EXPECTED_WRAP_ID" >&2
    echo "         (both sides lowercased; this is a real mismatch, not a case-only difference)" >&2
    exit 8
fi
echo "[verify] using manager-imported wrap-key $WRAP_ID (matches $EXPECTED_FILE)"

# H-V2: capture put-wrapped output to a log so the failure path can emit a
# clearly-formatted FAILED banner with both expected/actual ids and the
# tail of the tool's own diagnostics. Exit 9 is distinct from existing 1/3/4/5
# and the new 6/7/8 above.
echo "[verify] put-wrapped $WRAPPED with $WRAP_ID"
PUT_LOG=${OUT_DIR}/put_wrapped.log
if ! shell -a put-wrapped --wrap-id "$WRAP_ID" --in "$WRAPPED" >"$PUT_LOG" 2>&1; then
    echo "[verify] === FAILED — put-wrapped did not authenticate ===" >&2
    echo "[verify] expected wrap-id : $EXPECTED_WRAP_ID" >&2
    echo "[verify] actual wrap-id   : $WRAP_ID" >&2
    tail -10 "$PUT_LOG" >&2
    exit 9
fi

echo "[verify] reading recovered victim public key"
shell -a get-public-key -i 0x0042 -t asymmetric-key --out "$PUBKEY_AFTER" >/dev/null

echo "[verify] diffing public keys (before-deletion vs after-unwrap):"
if diff -q "$PUBKEY" "$PUBKEY_AFTER" >/dev/null; then
    echo "[verify] === MATCH — wrap-key bytes are byte-for-byte identical ==="
    sha256sum "$PUBKEY" "$PUBKEY_AFTER"
    exit 0
else
    # H-V2: explicit FAILED banner with both ids on the diff failure path
    # so the operator gets the same actionable diagnostic on a mismatch as
    # on a put-wrapped auth failure. sha256sum on BOTH success and failure
    # paths makes the byte-fingerprints visible either way.
    echo "[verify] ============================================================" >&2
    echo "[verify] === FAILED — recovered public key MISMATCHES the snapshot ==" >&2
    echo "[verify] expected wrap-id : $EXPECTED_WRAP_ID" >&2
    echo "[verify] actual wrap-id   : $WRAP_ID" >&2
    diff "$PUBKEY" "$PUBKEY_AFTER" >&2 || true
    sha256sum "$PUBKEY" "$PUBKEY_AFTER" >&2
    exit 1
fi
