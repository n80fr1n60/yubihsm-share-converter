#!/usr/bin/env bash
# Stage a fresh end-to-end test on a factory-reset YubiHSM2:
#   1. Drive `yubihsm-setup ksp` non-interactively → fresh wrap-key on
#      the HSM, plus 3 legacy-format shares (threshold 2) printed to
#      stdout. Captured to ${OUT_DIR}/legacy.txt.
#   2. Generate a throwaway asymmetric key (0x0042, ECP256, exportable
#      under wrap) and snapshot its public key.
#   3. Export-wrap the asym key under the freshly-created wrap-key
#      → ${OUT_DIR}/wrapped_victim.bin.
#   4. Delete the wrap-key, the app auth-key, and the asym key, leaving
#      only the default auth-key. The HSM is now ready for
#      `yubihsm-manager` to re-create the wrap-key from the converted
#      shares.
#
# After this script:
#   * Run the converter (R4-3 dual-knob disk-stdout gate — the gate
#     requires BOTH `YHSC_ALLOW_DISK_STDOUT=1` in a history-safe shell
#     AND `--i-accept-disk-output` on the command line; the env-var
#     alone is too weak because it can be injected without operator
#     intent via .bashrc / SetEnv / sudo env_keep / container -e):
#       set +o history
#       export YHSC_ALLOW_DISK_STDOUT=1
#       cargo run --release --manifest-path ../Cargo.toml -- \
#           --resplit --i-accept-disk-output \
#           < ${OUT_DIR}/legacy.txt > ${OUT_DIR}/converted.txt
#   * Drive the manager:
#       OUT_DIR=${OUT_DIR} YHM_SHARES_FILE=${OUT_DIR}/converted.txt \
#           python3 drive_manager.py
#   * Verify:
#       OUT_DIR=${OUT_DIR} ./verify_roundtrip.sh
#
# Env:
#   CON          connector URL    (default: http://127.0.0.1:12345)
#   AUTHKEY      auth-key id      (default: 1)
#   PASSWORD     auth-key pwd     (default: password)
#   WRAP_ID      override wrap-key id (default: 0 = HSM picks)
#   N_SHARES     total shares produced (default: 3)
#   THRESHOLD    privacy threshold     (default: 2)
#   OUT_DIR      where to write artifacts (REQUIRED — H-3-3: hard-fail
#                with exit 7 if unset, to avoid stale-ceremony pollution
#                in /tmp; recommended `/dev/shm/keymat-$$`)
#
# Exit codes:
#   0 — success
#   3 — missing tool (yubihsm-setup or yubihsm-shell)
#   4 — HSM not at factory state
#   5 — share-count mismatch (extracted < N_SHARES)
#   6 — cleanup-trap partial rollback (orphaned objects left on HSM)
#   7 — OUT_DIR is unset (H-3-3)
#   8 — OUT_DIR hygiene refusal (symlink / wrong owner / wrong mode) [E-M2]

set -euo pipefail

# E-M2: tighten file-mode for all on-disk artefacts written by this script.
# Without this, the raw setup log + share lines would land mode 0644 on the
# default umask 0022, world-readable from any same-uid (or, with 0027 umask,
# same-group) process. umask 077 makes every file/dir created below this
# point mode 0600/0700 by default. Applies in the trap handler too.
umask 077

CREATED_WRAP_ID=""
CREATED_APP_AUTH_ID=""
CREATED_VICTIM_ID=""

cleanup() {
    local rc=$?
    set +e
    set +u
    local rb_failures=()
    if [ -n "$CREATED_VICTIM_ID" ]; then
        shell -a delete-object -i "$CREATED_VICTIM_ID" -t asymmetric-key >/dev/null 2>&1 \
            || rb_failures+=("victim:$CREATED_VICTIM_ID")
    fi
    if [ -n "$CREATED_WRAP_ID" ]; then
        shell -a delete-object -i "$CREATED_WRAP_ID" -t wrap-key >/dev/null 2>&1 \
            || rb_failures+=("wrap:$CREATED_WRAP_ID")
    fi
    if [ -n "$CREATED_APP_AUTH_ID" ]; then
        shell -a delete-object -i "$CREATED_APP_AUTH_ID" -t authentication-key >/dev/null 2>&1 \
            || rb_failures+=("authkey:$CREATED_APP_AUTH_ID")
    fi
    # Also shred the raw setup log (contains shares in plaintext before extraction).
    [ -n "${RAW:-}" ] && [ -f "$RAW" ] && shred -u "$RAW" >/dev/null 2>&1
    if [ $rc -ne 0 ]; then
        if [ ${#rb_failures[@]} -eq 0 ]; then
            echo "[stage] aborted (rc=$rc); rollback OK" >&2
        else
            echo "[stage] aborted (rc=$rc); ROLLBACK FAILED for: ${rb_failures[*]}" >&2
            echo "[stage]   --- HSM partially-provisioned; manual cleanup required ---" >&2
            echo "[stage]   Run: yubihsm-shell -p \$PASSWORD -a list-objects" >&2
            # v2 (architect C-1): bash's `return N` from an EXIT trap does NOT
            # change the script's final exit status; it stays at $? on entry.
            # Use `exit 6` to actually surface the partial-rollback condition.
            exit 6
        fi
    fi
    return $rc
}
trap cleanup EXIT

CON=${CON:-http://127.0.0.1:12345}
AUTHKEY=${AUTHKEY:-1}
PASSWORD=${PASSWORD:-password}
WRAP_ID=${WRAP_ID:-0}
N_SHARES=${N_SHARES:-3}
THRESHOLD=${THRESHOLD:-2}
# H-3-3: refuse to default OUT_DIR — for symmetry with verify_roundtrip.sh
# and drive_manager.py, all three scripts hard-fail uniformly when OUT_DIR
# is unset. README hardening recommends `OUT_DIR=/dev/shm/keymat-$$`; if the
# export is lost across a sub-shell, defaulting here would write artefacts
# (wrapped blob, raw setup log with shares) to /tmp where a stale prior-run
# id-file could later poison verify. Exit 7 — verify uses 5 for the same
# unset-OUT_DIR condition, but stage already uses 5 (share-count mismatch
# at line ~169) and 6 (cleanup partial-rollback). 7 is the lowest free code.
if [ -z "${OUT_DIR:-}" ]; then
    echo "[stage] OUT_DIR is unset. Refusing to default to /tmp — stale" >&2
    echo "        id-file or wrapped blob from prior ceremony could be" >&2
    echo "        silently consumed. Set OUT_DIR and re-run." >&2
    exit 7
fi

# E-M2: validate OUT_DIR is a safe working directory. Same-UID attacker could
# pre-plant a symlinked OUT_DIR pointing at a world-readable location, or pre-
# create the dir mode 0755. Reject all three pathological cases up front; the
# umask 077 above then guarantees any NEW files we create are 0600.
#   Exit 8: new code, next free after 3/4/5/6/7.
# Note: `-L` returns true for ALL symlinks (including dangling ones) since
# bash uses lstat(); ordering this check before the mkdir guards against a
# symlink-replacement race on first-run.
if [ -L "$OUT_DIR" ]; then
    echo "[stage] OUT_DIR is a symlink — refusing. Same-UID attacker could" >&2
    echo "        have pre-planted it. Set OUT_DIR to a real directory." >&2
    exit 8
fi
if [ ! -d "$OUT_DIR" ]; then
    # Create under the umask 077 above → mode 0700.
    mkdir -p "$OUT_DIR"
fi
# Owned by the running uid (rejects pre-planted attacker dir).
out_dir_uid="$(stat -c '%u' "$OUT_DIR")"
if [ "$out_dir_uid" != "$(id -u)" ]; then
    echo "[stage] OUT_DIR is not owned by uid $(id -u) (owner uid $out_dir_uid) — refusing." >&2
    exit 8
fi
# Mode 0700 (no group/other access).
out_dir_mode="$(stat -c '%a' "$OUT_DIR")"
if [ "$out_dir_mode" != "700" ]; then
    echo "[stage] OUT_DIR is not mode 0700 (got $out_dir_mode) — refusing." >&2
    echo "        Run: chmod 0700 \"\$OUT_DIR\" and re-run." >&2
    exit 8
fi

LEGACY=${OUT_DIR}/legacy.txt
RAW=${OUT_DIR}/legacy_setup_raw.log
WRAPPED=${OUT_DIR}/wrapped_victim.bin
PUBKEY=${OUT_DIR}/victim_pubkey.pem

# H-V1 (architect H-6): drop a stale wrap-id file from a previous failed
# run so the next ceremony can't be poisoned by it. drive_manager.py
# (atomically, mode 0600) rewrites this file on success; verify_roundtrip.sh
# refuses to proceed if it's missing.
rm -f "${OUT_DIR}/imported_wrap_id.txt"

shell()  { yubihsm-shell --connector "$CON" -p "$PASSWORD" --authkey "$AUTHKEY" "$@"; }

for tool in yubihsm-setup yubihsm-shell; do
    command -v "$tool" >/dev/null || { echo "[stage] missing tool: $tool" >&2; exit 3; }
done
# E-M2: OUT_DIR mkdir + hygiene validation happen earlier (above), under the
# umask 077 gate. Don't re-mkdir here.

echo "[stage] verifying HSM is at factory state (1 object: default auth-key)"
# R12-02 parity gate: this grep's format-shape is exercised against
# tests/fixtures/device-transcripts/yubihsm-shell-list-objects.txt via
# scripts/tests/test_transcript_parity.sh — see that test's "Parser 1" block.
n_obj=$(shell -a list-objects 2>/dev/null | grep -c '^id:')
if [ "$n_obj" != "1" ]; then
    echo "[stage] error: HSM has $n_obj objects; expected 1 (default auth-key)." >&2
    echo "        Run \`yubihsm-shell -a reset\` first if this is a throwaway device." >&2
    exit 4
fi

echo "[stage] driving 'yubihsm-setup ksp' to generate legacy shares ($THRESHOLD-of-$N_SHARES)"
# Answer sequence (see yubihsm-setup/src/main.rs): RSA-decrypt? domains,
# wrap-id, n shares, threshold, blank-Enter, then per-share (ready?, recorded?)
# pairs, then app auth-key id, password, audit-key? — `-d -e` keep the
# default auth-key alive and skip on-disk wrap exports.
{
    printf 'n\n'                  # no RSA decrypt caps
    printf '1\n'                  # domains
    printf '%s\n' "$WRAP_ID"      # wrap-key id (0 = auto)
    printf '%s\n' "$N_SHARES"
    printf '%s\n' "$THRESHOLD"
    printf '\n'                   # press-Enter to start recording shares
    for _ in $(seq 1 "$N_SHARES"); do
        printf 'y\ny\n'           # ready? + recorded? per share
    done
    printf '0\n'                  # app auth-key id
    printf 'testpw\n'             # app auth-key password
    printf 'n\n'                  # no audit key
} | yubihsm-setup -d -e -p "$PASSWORD" --authkey "$AUTHKEY" --connector "$CON" ksp \
    > "$RAW" 2>&1

# yubihsm-setup ksp has now created a wrap-key + app auth-key on the HSM.
# Discover and TRACK them BEFORE the share-extraction step, so a parse
# failure below still hits the cleanup trap with non-empty CREATED_*
# (otherwise leaked objects survive the abort path — see H8 v3-review N12).
# R12-02 parity gate: both awk extractors below are exercised against
# tests/fixtures/device-transcripts/yubihsm-shell-list-objects.txt via
# scripts/tests/test_transcript_parity.sh ("Parser 2" / "Parser 3" blocks).
# The post-R10-L2-hotfix column-anchored `$4 == "wrap-key"` predicate is
# load-bearing — the pre-hotfix `/^wrap-key,/` regex modelled a fabricated
# test-stub format and missed the real `id: 0xXXXX, type: T, …` shape.
NEW_WRAP_ID=$(shell -a list-objects 2>/dev/null \
    | awk -F'[, ]+' '$4 == "wrap-key" {print $2; exit}')
CREATED_WRAP_ID="$NEW_WRAP_ID"
APP_AUTH_ID=$(shell -a list-objects 2>/dev/null \
    | awk -F'[, ]+' '$4 == "authentication-key" && $2 != "0x0001" {print $2; exit}')
CREATED_APP_AUTH_ID="$APP_AUTH_ID"
echo "[stage] HSM now holds wrap-key $NEW_WRAP_ID and app auth-key $APP_AUTH_ID"

# Strip ANSI escapes and pull out the share lines (T-N-base64{70 chars}).
# v2 (H-Sc1): pipeline lives in scripts/_extract_shares.sh now — wider
# regex (T up to 2 digits, N up to 3 digits) for >9-share ceremonies plus
# an awk sanity filter rejecting 0/out-of-range candidates so a transient
# log line that happens to match can't masquerade as a real share.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
"$SCRIPT_DIR/_extract_shares.sh" "$RAW" > "$LEGACY"

if [ "$(wc -l < "$LEGACY")" != "$N_SHARES" ]; then
    echo "[stage] error: extracted $(wc -l < "$LEGACY") shares from setup output, expected $N_SHARES." >&2
    echo "        Raw log left at $RAW." >&2
    exit 5
fi
# Share extraction succeeded — shred the plaintext-shares raw log immediately.
shred -u "$RAW" >/dev/null 2>&1 || true
echo "[stage] captured $N_SHARES legacy shares → $LEGACY"

echo "[stage] generating victim asymmetric key 0x0042 (ECP256, exportable-under-wrap)"
shell -a generate-asymmetric-key -i 0x0042 -l "wrap-test-victim" \
        -d 1 -c "sign-ecdsa,exportable-under-wrap" -A ecp256 >/dev/null
CREATED_VICTIM_ID=0x0042

echo "[stage] export-wrapping 0x0042 under $NEW_WRAP_ID → $WRAPPED"
shell -a get-wrapped -i 0x0042 -t asymmetric-key \
        --wrap-id "$NEW_WRAP_ID" --out "$WRAPPED" >/dev/null

echo "[stage] snapshotting victim public key → $PUBKEY"
shell -a get-public-key -i 0x0042 -t asymmetric-key --out "$PUBKEY" >/dev/null

echo "[stage] deleting test objects from the HSM"
shell -a delete-object -i 0x0042 -t asymmetric-key >/dev/null
CREATED_VICTIM_ID=""
shell -a delete-object -i "$NEW_WRAP_ID" -t wrap-key >/dev/null
CREATED_WRAP_ID=""
shell -a delete-object -i "$APP_AUTH_ID" -t authentication-key >/dev/null
CREATED_APP_AUTH_ID=""

echo "[stage] state after cleanup:"
shell -a list-objects 2>/dev/null | grep '^id:' | sed 's/^/        /'

cat <<EOF
[stage] === ready ===
        legacy shares       : $LEGACY
        recovered wrap-id   : $NEW_WRAP_ID  (the manager must re-create this id)
        wrapped victim blob : $WRAPPED  (sha256 $(sha256sum "$WRAPPED" | cut -d' ' -f1))
        victim pubkey       : $PUBKEY  (sha256 $(sha256sum "$PUBKEY"   | cut -d' ' -f1))

        next:
          # R4-3 dual-knob: the converter's disk-stdout gate refuses
          # output redirects unless BOTH knobs are supplied:
          #   1. YHSC_ALLOW_DISK_STDOUT=1 (env), set in a history-safe
          #      shell so the assignment doesn't land in ~/.bash_history.
          #   2. --i-accept-disk-output (CLI), supplied per-invocation;
          #      defeats env-only injection (.bashrc, SetEnv, sudo
          #      env_keep, container -e).
          # \`set +o history\` (Option A) is the simplest choice for the
          # history-safety half — it stops shell history from recording
          # the env-var assignment.
          set +o history
          export YHSC_ALLOW_DISK_STDOUT=1
          cargo run --release --manifest-path \\
              "$(dirname "$(realpath "$0")")/../Cargo.toml" -- \\
              --resplit --i-accept-disk-output \\
              < "$LEGACY" > "${OUT_DIR}/converted.txt"
          OUT_DIR="$OUT_DIR" YHM_SHARES_FILE="${OUT_DIR}/converted.txt" \\
              python3 "$(dirname "$(realpath "$0")")/drive_manager.py"
          OUT_DIR="$OUT_DIR" "$(dirname "$(realpath "$0")")/verify_roundtrip.sh"
EOF
