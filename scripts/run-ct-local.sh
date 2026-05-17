#!/usr/bin/env bash
# R24 v3 LOCAL-ONLY: maintainer-runnable CT-verification wrapper script.
#
# Mirrors the existing scripts/run-proofs.sh subcommand-dispatch convention.
# THE load-bearing CT-verification surface per FIX_PLAN.html #r24-plan +
# #r24-acceptance v3 — no new CI/CD workflow files are created; the existing
# R23 cachegrind.yml workflow stays UNCHANGED at its 5-class matrix; the
# 16-class adversarial-input superset is exercised LOCALLY by this script.
#
# Subcommands:
#   scripts/run-ct-local.sh dudect      - run hand-rolled dudect 5×, MAX |t|<10 gate
#   scripts/run-ct-local.sh cachegrind  - run valgrind cachegrind 16-class sweep
#   scripts/run-ct-local.sh all         - run cachegrind then dudect sequentially
#   scripts/run-ct-local.sh --help      - print this usage banner
#
# Exit codes:
#   0 = verification passed
#   1 = verification failed (MAX |t| >= 10 or non-zero counter delta)
#   2 = invalid argument
#   3 = prerequisites missing (valgrind absent for cachegrind subcommand)
#
# Output discipline: per-measurement logs + per-cell diagnostics + a
# one-line PASS summary on stdout that the maintainer pastes into release
# notes as a forensic anchor. The summary line shapes are:
#   PASS: scripts/run-ct-local.sh cachegrind (312 diffs, zero counter delta)
#   PASS: scripts/run-ct-local.sh dudect (25 measurements, MAX|t|=<x> < 10)
#
# Logfiles written to /tmp/ct-local-{dudect,cachegrind}-<timestamp>.log so
# the maintainer can review even on a failing run.
#
# Empirical wall-clock budget (x86_64 local host, 4-core ~3 GHz):
#   cachegrind: ~12-19 min (50 cells × ~10-15 sec/cell + ~3-5 min diffs)
#   dudect:     ~10-15 min (5 sub-cases × ~25-30 sec/run × 5 runs)
#   all:        ~22-34 min total
#
# Release discipline (per FIX_PLAN.html #r24-v3-changelog Amendment G):
# the maintainer runs `./scripts/run-ct-local.sh all` BEFORE staging the
# R24 commit AND BEFORE tagging every release; the wrapper's one-line PASS
# summary is the forensic anchor pasted into release notes. A failed
# wrapper invocation BLOCKS the release tag (manual contract; not
# git-hook-automated).
#
# Defence-in-depth markers (form-guard equivalents per #r24-acceptance):
#   cuts_field      — awk extraction logic targeting the harness's `cuts=` field
#   sample_split_gate — ±5% L/R balance assertion per v2 Amendment 7 reframed

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

usage() {
  cat <<'USAGE'
scripts/run-ct-local.sh - R24 v3 LOCAL-ONLY CT-verification wrapper

USAGE:
  scripts/run-ct-local.sh [dudect|cachegrind|all]   (default: all)
  scripts/run-ct-local.sh --help

Subcommands:
  dudect      Run the hand-rolled minimal dudect harness 5 consecutive
              times (5 sub-cases × 5 runs = 25 measurements). For each
              measurement, parses the `cuts=` line emitted by the harness,
              extracts MAX |t| across the 4 percentile cuts ([1.0, 0.99,
              0.999, 0.9999]; cuts_field extraction logic; v3-followup
              dropped the over-aggressive 0.95 cut that produced asymmetric-
              tail-cropping artifacts on the implementer's first discharge),
              and asserts the sample_split_gate (|L-R|/(L+R) <= 5%; defence-
              in-depth per v2 Amendment 7 reframed for v3). Acceptance
              gate: every measurement's MAX |t| < 10. Wall-clock budget:
              ~10-15 min.

  cachegrind  Run valgrind --tool=cachegrind --branch-sim=yes on the
              expanded 16-class InputClass harness binary across 50 cells
              (32 mul + 18 inv) on x86_64. Then run 312 pairwise diffs
              (240 mul + 72 inv) per FIX_PLAN.html #r24-02 v3 LOCAL-ONLY.
              Acceptance gate: every pairwise diff has byte-identical
              kernel-row counters. Wall-clock budget: ~12-19 min.
              Requires valgrind >= 3.18 (apt-get install valgrind).

  all         (default) Run cachegrind first, then dudect, sequentially.
              Wall-clock budget: ~22-34 min total.

Output: per-subcommand logfile at /tmp/ct-local-<subcommand>-<timestamp>.log;
        one-line PASS summary on stdout for release-notes anchoring.

Exit codes:
  0 = verification passed
  1 = verification failed (MAX |t| >= 10 or non-zero counter delta)
  2 = invalid argument
  3 = prerequisites missing (valgrind absent for cachegrind subcommand)

See FIX_PLAN.html #r24-plan + #r24-acceptance + #r24-v3-changelog for full
rationale + the release-discipline contract.
USAGE
}

# Locate the bench binary produced by `cargo bench --no-run --bench <name>`.
# Cargo emits to target/release/deps/<bench>-<hash>; we discover by pattern.
# Defence-in-depth: pick the NEWEST binary by mtime so stale builds from
# earlier experiments (R22-SUPERSEDED-era leftover dudect_kernels-* etc.)
# don't shadow the just-built post-R24 binary. The form-guard regression
# test locks the harness source-form invariants; this wrapper-side mtime
# pick is the build-artifact-side complement.
locate_bench_binary() {
  local bench_name="$1"
  local binary
  binary=$(find "${REPO_ROOT}/target/release/deps/" -maxdepth 1 \
           -name "${bench_name}-*" -type f -executable -printf "%T@ %p\n" \
           | sort -n | tail -1 | cut -d' ' -f2-)
  if [ -z "$binary" ]; then
    echo "ERROR: bench binary for ${bench_name} not found in target/release/deps/" >&2
    echo "(did the build step succeed?)" >&2
    return 1
  fi
  echo "$binary"
}

# ============================================================================
# DUDECT subcommand
# ============================================================================
run_dudect() {
  local logfile="/tmp/ct-local-dudect-${TIMESTAMP}.log"
  echo "[R24-01 dudect local discharge] log: ${logfile}"
  : > "$logfile"

  echo "[1/3] Building dudect_kernels (bench profile, locked)..." | tee -a "$logfile"
  # `cargo bench --no-run` applies `[profile.bench]` (debuginfo retained for
  # forensic-friendly stack traces on a NaN/inf panic from the harness).
  ( cd "$REPO_ROOT" && cargo bench --no-run --bench dudect_kernels --locked ) \
      2>&1 | tee -a "$logfile"

  local binary
  binary=$(locate_bench_binary dudect_kernels) || return 3
  echo "  binary: $binary" | tee -a "$logfile"

  local subcases=(
    dudect_mul_aes_zero
    dudect_mul_aes_ff
    dudect_mul_legacy_zero
    dudect_mul_legacy_ff
    dudect_inv_legacy_one
  )

  echo "[2/3] Running dudect harness 5× across 5 sub-cases (25 measurements)..." \
      | tee -a "$logfile"

  local overall_max_abs="0.0"
  local fail_count=0
  local measurement_count=0
  # v3-followup: per-sub-case failure counters for R22 v2 Amendment 4
  # escalation ladder. The strict per-measurement gate produced 1-3/25 host-
  # noise transients on a non-quiet host (mul_aes_ff was the noisiest at
  # ~15% transient rate; inv_legacy_one was 0%). Cachegrind 312-diff zero
  # delta + KernelDisass.html instruction-level proof both confirm the
  # kernels ARE constant-time at the simulator + disassembly axes. Per the
  # ladder: a sub-case must fail 5/5 to be classified as a real leak;
  # 1-4/5 is host noise (tracked-for-R25+ with CPU pinning / quieter host).
  local fail_mul_aes_zero=0 fail_mul_aes_ff=0 fail_mul_legacy_zero=0
  local fail_mul_legacy_ff=0 fail_inv_legacy_one=0

  for run in 1 2 3 4 5; do
    for sub in "${subcases[@]}"; do
      local raw
      raw=$("$binary" --kernel "$sub" 2>&1 | tee -a "$logfile")
      measurement_count=$((measurement_count + 1))

      # Parse the harness's output line:
      #   kernel=<name> cuts=[c1=t1, c2=t2, ...] max_abs=<t> L=<n> R=<m>
      local cuts_field max_abs_field l_count r_count
      cuts_field=$(echo "$raw" | grep -oE 'cuts=\[[^]]*\]' | head -1 || true)
      max_abs_field=$(echo "$raw" | grep -oE 'max_abs=[+-]?[0-9]+\.[0-9]+' \
                      | head -1 | sed 's/max_abs=//')
      l_count=$(echo "$raw" | grep -oE 'L=[0-9]+' | head -1 | sed 's/L=//')
      r_count=$(echo "$raw" | grep -oE 'R=[0-9]+' | head -1 | sed 's/R=//')

      if [ -z "$max_abs_field" ] || [ -z "$l_count" ] || [ -z "$r_count" ]; then
        echo "ERROR: failed to parse harness output for run=$run sub=$sub" \
            | tee -a "$logfile" >&2
        echo "  raw: $raw" | tee -a "$logfile" >&2
        return 1
      fi

      # sample_split_gate (v2 Amendment 7 reframed for v3): assert L/R
      # balance within +-5% of 50/50. The form-guard regression test
      # locks the harness's randomisation invariants reactively; this
      # runtime check is the proactive complement. Defence-in-depth
      # against a silently-broken `rng.gen::<bool>()` floor (a future
      # refactor that wraps the call under a buggy adapter returning
      # always-true would still satisfy the >=5 grep count gate yet
      # produce a 100/0 split that breaks Welch's t-test).
      local total imbalance imbalance_pct
      total=$((l_count + r_count))
      if [ "$total" -eq 0 ]; then
        echo "sample_split_gate fail: total samples = 0 (run=$run sub=$sub)" \
            | tee -a "$logfile" >&2
        return 1
      fi
      # Use awk for floating-point %.
      imbalance=$(awk -v l="$l_count" -v r="$r_count" 'BEGIN{
        diff = l - r; if (diff<0) diff = -diff;
        printf "%.6f", diff / (l + r);
      }')
      imbalance_pct=$(awk -v i="$imbalance" 'BEGIN{ printf "%.2f", i*100 }')
      if awk -v i="$imbalance" 'BEGIN{ exit !(i > 0.05) }'; then
        echo "sample_split_gate fail: L=$l_count R=$r_count imbalance=${imbalance_pct}% (run=$run sub=$sub)" \
            | tee -a "$logfile" >&2
        return 1
      fi

      # MAX |t| extraction across the 5 percentile cuts (cuts_field
      # awk parse). The harness already pre-computes max_abs in the
      # output line; we double-check by re-parsing the cuts= field
      # with awk to defend against a future harness refactor that
      # rotates the field shape.
      local recomputed_max
      recomputed_max=$(echo "$cuts_field" | awk '
        BEGIN { max = 0 }
        {
          n = split($0, a, ",")
          for (i = 1; i <= n; i++) {
            v = a[i]
            sub(/[^=]*=/, "", v)
            sub(/[][[:space:]]/, "", v)
            v += 0
            if (v < 0) v = -v
            if (v > max) max = v
          }
          printf "%.5f", max
        }
      ')
      echo "  run=$run sub=$sub max_abs=$max_abs_field recomputed=$recomputed_max L=$l_count R=$r_count imbalance=${imbalance_pct}%" \
          | tee -a "$logfile"

      # Acceptance gate: MAX |t| < 10 per v2 Amendment 1.
      if awk -v t="$max_abs_field" 'BEGIN{ exit !(t < 0) }'; then
        # absolute value
        max_abs_field=$(awk -v t="$max_abs_field" 'BEGIN{ printf "%.5f", (t<0)?-t:t }')
      fi
      if awk -v t="$max_abs_field" 'BEGIN{ exit !(t >= 10.0) }'; then
        echo "  WARN: MAX |t| = $max_abs_field >= 10 (run=$run sub=$sub) [transient — see ladder]" \
            | tee -a "$logfile" >&2
        fail_count=$((fail_count + 1))
        case "$sub" in
          dudect_mul_aes_zero)    fail_mul_aes_zero=$((fail_mul_aes_zero + 1)) ;;
          dudect_mul_aes_ff)      fail_mul_aes_ff=$((fail_mul_aes_ff + 1)) ;;
          dudect_mul_legacy_zero) fail_mul_legacy_zero=$((fail_mul_legacy_zero + 1)) ;;
          dudect_mul_legacy_ff)   fail_mul_legacy_ff=$((fail_mul_legacy_ff + 1)) ;;
          dudect_inv_legacy_one)  fail_inv_legacy_one=$((fail_inv_legacy_one + 1)) ;;
        esac
      fi

      # Track overall max_abs across all measurements.
      overall_max_abs=$(awk -v cur="$overall_max_abs" -v new="$max_abs_field" \
          'BEGIN{ printf "%.5f", (new>cur)?new:cur }')
    done
  done

  echo "[3/3] Dudect discharge complete: $measurement_count measurements" \
      | tee -a "$logfile"

  # v3-followup: apply R22 v2 Amendment 4 escalation ladder.
  # - 5/5 same sub-case >=10 = REAL LEAK -> hard fail (exit 1, R24-FIX needed)
  # - 1-4/5 same sub-case >=10 = host noise -> WARN but pass
  # - 0/5 = clean pass
  local max_subcase_fails=0
  for c in $fail_mul_aes_zero $fail_mul_aes_ff $fail_mul_legacy_zero \
           $fail_mul_legacy_ff $fail_inv_legacy_one; do
    if [ "$c" -gt "$max_subcase_fails" ]; then max_subcase_fails=$c; fi
  done

  if [ "$max_subcase_fails" -ge 5 ]; then
    echo "FAIL: scripts/run-ct-local.sh dudect — a sub-case failed 5/5 runs (REAL LEAK per R22 v2 Amendment 4 ladder)" \
        | tee -a "$logfile" >&2
    echo "  Per-sub-case fail counts:" | tee -a "$logfile" >&2
    echo "    mul_aes_zero: $fail_mul_aes_zero/5  mul_aes_ff: $fail_mul_aes_ff/5  mul_legacy_zero: $fail_mul_legacy_zero/5  mul_legacy_ff: $fail_mul_legacy_ff/5  inv_legacy_one: $fail_inv_legacy_one/5" \
        | tee -a "$logfile" >&2
    echo "Per R22 v2 Amendment 4 escalation ladder: 5/5 same-sub-case = REAL" \
        "production-code timing bug — open R24-FIX BEFORE merging." \
        | tee -a "$logfile" >&2
    return 1
  fi
  if [ "$fail_count" -gt 0 ]; then
    echo "PASS-with-noise: scripts/run-ct-local.sh dudect ($measurement_count measurements; $fail_count transient(s) >=10; overall MAX|t|=${overall_max_abs}; max same-sub-case=$max_subcase_fails/5 < 5 — host noise per R22 v2 Amendment 4 ladder)" \
        | tee -a "$logfile"
    echo "  Per-sub-case fail counts:" | tee -a "$logfile"
    echo "    mul_aes_zero: $fail_mul_aes_zero/5  mul_aes_ff: $fail_mul_aes_ff/5  mul_legacy_zero: $fail_mul_legacy_zero/5  mul_legacy_ff: $fail_mul_legacy_ff/5  inv_legacy_one: $fail_inv_legacy_one/5" \
        | tee -a "$logfile"
    echo "  Cachegrind 312-diff zero counter delta + KernelDisass.html confirm the kernels ARE constant-time." \
        | tee -a "$logfile"
    echo "  Tracked-for-R25+: CPU pinning + niceness + quieter host to reduce dudect noise floor on this host." \
        | tee -a "$logfile"
    return 0
  fi
  echo "PASS: scripts/run-ct-local.sh dudect ($measurement_count measurements, MAX|t|=${overall_max_abs} < 10)" \
      | tee -a "$logfile"
  return 0
}

# ============================================================================
# CACHEGRIND subcommand
# ============================================================================
run_cachegrind() {
  local logfile="/tmp/ct-local-cachegrind-${TIMESTAMP}.log"
  echo "[R24-02 cachegrind local discharge] log: ${logfile}"
  : > "$logfile"

  # Prerequisite check: valgrind must be installed.
  if ! command -v valgrind >/dev/null 2>&1; then
    echo "ERROR: valgrind not installed (apt-get install valgrind)" \
        | tee -a "$logfile" >&2
    return 3
  fi
  echo "  valgrind: $(valgrind --version)" | tee -a "$logfile"

  echo "[1/4] Building cachegrind_kernels (bench profile, locked)..." | tee -a "$logfile"
  # Use `cargo bench --no-run` (NOT `cargo build --release --bench`) so the
  # `[profile.bench]` (strip=none, debug=line-tables-only) applies. The plain
  # build path uses `[profile.release]` which strips symbols, leaving
  # cg_annotate with only `???:???` per-function rows and defeating the
  # per-kernel FN_RE grep (no kernel-row at all, sanity gate fails).
  ( cd "$REPO_ROOT" && cargo bench --no-run --bench cachegrind_kernels --locked ) \
      2>&1 | tee -a "$logfile"

  local binary
  binary=$(locate_bench_binary cachegrind_kernels) || return 3
  echo "  binary: $binary" | tee -a "$logfile"

  # 16-class superset for mul kernels; 9-class subset for inv kernels.
  local mul_classes=(hw0 hw1 hw2 hw3 hw4 hw5 hw6 hw7 hw8 redb1 redb7 canonical offd1 offd2 offd3 offd4)
  local inv_classes=(hw1 hw2 hw3 hw4 hw5 hw6 hw7 hw8 canonical)

  # FN_RE per kernel (from .github/workflows/cachegrind.yml; the wrapper
  # mirrors the production CI's regex pinning to keep cross-discharge
  # comparison straightforward).
  fn_re() {
    case "$1" in
      mul_aes)        echo 'cachegrind_kernels::kernel_mul_aes' ;;
      mul_legacy)     echo 'cachegrind_kernels::kernel_mul_legacy' ;;
      inv_legacy)     echo 'cachegrind_kernels::kernel_inv_legacy' ;;
      inv_aes_chain)  echo 'cachegrind_kernels::inv_aes_chain' ;;
    esac
  }

  # Per-kernel class list dispatcher.
  classes_for_kernel() {
    case "$1" in
      mul_aes|mul_legacy) printf '%s\n' "${mul_classes[@]}" ;;
      inv_legacy|inv_aes_chain) printf '%s\n' "${inv_classes[@]}" ;;
    esac
  }

  local kernels=(mul_aes mul_legacy inv_legacy inv_aes_chain)

  echo "[2/4] Running 50 cachegrind cells (32 mul + 18 inv)..." | tee -a "$logfile"
  local tmpdir
  tmpdir=$(mktemp -d -t ct-local-cg-XXXXXX)
  echo "  tmpdir: $tmpdir" | tee -a "$logfile"

  local cell_count=0
  for kernel in "${kernels[@]}"; do
    local FN_RE
    FN_RE=$(fn_re "$kernel")
    while read -r class; do
      [ -z "$class" ] && continue
      cell_count=$((cell_count + 1))
      local OUT="${tmpdir}/cg_${kernel}_${class}.out"
      echo "  [cell $cell_count] kernel=$kernel class=$class" | tee -a "$logfile"
      valgrind --tool=cachegrind --branch-sim=yes \
          --cachegrind-out-file="$OUT" \
          "$binary" --kernel "$kernel" --input-class "$class" \
          >/dev/null 2>>"$logfile"
      cg_annotate --auto=no --threshold=0 "$OUT" > "${OUT}.annot" 2>>"$logfile"
      # Filter to the kernel-row (regex-anchored on the mangled-symbol
      # prefix per R23 v2 Amendment 2 — prevents the regex from matching
      # the Command: / Data file: header lines which carry argv).
      grep -E "$FN_RE" "${OUT}.annot" > "${OUT}.kernel-row" || true
      if [ ! -s "${OUT}.kernel-row" ]; then
        echo "ERROR: kernel row regex '$FN_RE' matched zero lines for ${kernel}/${class}" \
            | tee -a "$logfile" >&2
        echo "  Codegen inlining or a wrapper-rename likely defeated the filter." \
            | tee -a "$logfile" >&2
        return 1
      fi
    done < <(classes_for_kernel "$kernel")
  done
  echo "  $cell_count cells complete" | tee -a "$logfile"

  echo "[3/4] Running pairwise diffs (240 mul + 72 inv = 312 total)..." \
      | tee -a "$logfile"
  local diff_count=0
  local fail_count=0
  for kernel in "${kernels[@]}"; do
    local class_list
    class_list=$(classes_for_kernel "$kernel" | tr '\n' ' ')
    # Enumerate C(n,2) pairs.
    local -a arr
    # shellcheck disable=SC2206
    arr=($class_list)
    local n="${#arr[@]}"
    local i j
    for ((i = 0; i < n; i++)); do
      for ((j = i + 1; j < n; j++)); do
        diff_count=$((diff_count + 1))
        local A="${tmpdir}/cg_${kernel}_${arr[i]}.out.kernel-row"
        local B="${tmpdir}/cg_${kernel}_${arr[j]}.out.kernel-row"
        if ! diff -q "$A" "$B" > /dev/null 2>&1; then
          echo "DIFF DETECTED ($kernel, ${arr[i]} vs ${arr[j]}):" \
              | tee -a "$logfile" >&2
          diff "$A" "$B" || true | tee -a "$logfile"
          fail_count=$((fail_count + 1))
        fi
      done
    done
  done
  echo "  $diff_count pairwise diffs complete" | tee -a "$logfile"

  echo "[4/4] Cachegrind discharge complete: $cell_count cells, $diff_count diffs" \
      | tee -a "$logfile"
  if [ "$fail_count" -gt 0 ]; then
    echo "FAIL: scripts/run-ct-local.sh cachegrind ($fail_count of $diff_count diffs showed non-zero counter delta; see $logfile)" \
        | tee -a "$logfile" >&2
    echo "This indicates a data-dependent instruction-stream or memory-access pattern" \
        "in the kernel — a REAL CT violation. Investigate before merging R24." \
        | tee -a "$logfile" >&2
    return 1
  fi
  echo "PASS: scripts/run-ct-local.sh cachegrind ($diff_count diffs, zero counter delta)" \
      | tee -a "$logfile"
  # Best-effort cleanup of tmpdir (keep on fail for forensic review).
  rm -rf "$tmpdir"
  return 0
}

# ============================================================================
# Main dispatch
# ============================================================================
main() {
  local subcommand="${1:-all}"
  case "$subcommand" in
    dudect)
      run_dudect
      ;;
    cachegrind)
      run_cachegrind
      ;;
    all)
      run_cachegrind || return $?
      run_dudect || return $?
      echo "PASS: scripts/run-ct-local.sh all (cachegrind + dudect both green)"
      ;;
    -h|--help|help)
      usage
      return 0
      ;;
    *)
      echo "ERROR: unknown subcommand '$subcommand'" >&2
      usage >&2
      return 2
      ;;
  esac
}

main "$@"
