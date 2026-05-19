#!/usr/bin/env bash
# R24 v3 + R25-01 LOCAL-ONLY: maintainer-runnable CT-verification wrapper.
#
# Mirrors the existing scripts/run-proofs.sh subcommand-dispatch convention.
# THE load-bearing CT-verification surface per FIX_PLAN.html #r24-plan +
# #r24-acceptance v3 + #r25-plan + #r25-01 — no new CI/CD workflow files are
# created; the existing R23 cachegrind.yml workflow stays UNCHANGED at its
# 5-class matrix; the 16-class adversarial-input superset (R24-02) + the
# TIMECOP-style memcheck-taint sweep (R25-01) are exercised LOCALLY by this
# script.
#
# Subcommands:
#   scripts/run-ct-local.sh dudect      - run hand-rolled dudect 20×, ADVISORY-only
#   scripts/run-ct-local.sh cachegrind  - run valgrind cachegrind 16-class sweep (LOAD-BEARING gate)
#   scripts/run-ct-local.sh memcheck    - run valgrind memcheck-taint 5×N=3 sweep (R25-01; LOAD-BEARING gate)
#   scripts/run-ct-local.sh all         - run cachegrind + dudect + memcheck sequentially
#   scripts/run-ct-local.sh --help      - print this usage banner
#
# Exit codes (v4 amendment path (c) at FIX_PLAN.html #r24-v4-amendment;
# R26-01 pinning/niceness are ADVISORY-only — failure to probe taskset
# or to elevate niceness logs a warning + continues at default scheduling;
# does NOT affect exit codes):
#   0 = verification passed (cachegrind LOAD-BEARING zero counter delta;
#       dudect ADVISORY exits 0 regardless of transients; R26-01 pinning
#       + niceness ADVISORY-only — degraded probe still exits 0)
#   1 = LOAD-BEARING verification failed (cachegrind non-zero counter delta;
#       sample_split_gate breach; or harness-internal NaN/inf/parse error)
#   2 = invalid argument
#   3 = prerequisites missing (valgrind absent for cachegrind subcommand)
#
# Output discipline: per-measurement logs + per-cell diagnostics + a
# one-line summary on stdout that the maintainer pastes into release
# notes as a forensic anchor. The summary line shapes are:
#   PASS:     scripts/run-ct-local.sh cachegrind (312 diffs, zero counter delta)
#   ADVISORY: scripts/run-ct-local.sh dudect (100 measurements; overall MAX|t|=<x>;
#             cachegrind 312/312 zero delta is the LOAD-BEARING gate per v4 amendment)
#   ADVISORY-with-transients: scripts/run-ct-local.sh dudect (100 measurements;
#             <n>/100 transient(s) |t|>=10; overall MAX|t|=<x>; cachegrind 312/312
#             zero delta + KernelDisass.html are the LOAD-BEARING gates per v4 amendment)
#
# Logfiles written to /tmp/ct-local-{dudect,cachegrind}-<timestamp>.log so
# the maintainer can review even on a failing run.
#
# Empirical wall-clock budget (x86_64 local host, 4-core ~3 GHz):
#   cachegrind: ~12-19 min (50 cells × ~10-15 sec/cell + ~3-5 min diffs)
#   dudect:     ~40-60 min (5 sub-cases × ~25-30 sec/run × 20 runs at
#               SAMPLES = 1_000_000 per sub-case; R26 v2 wall-clock note:
#               30-60 min realistic on a 5×-faster host vs the conservative
#               ~2 hr ceiling for reference-class hosts)
#   all:        ~45-70 min total
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
scripts/run-ct-local.sh - R24 v3 + R25-01 LOCAL-ONLY CT-verification wrapper

USAGE:
  scripts/run-ct-local.sh [dudect|cachegrind|memcheck|all]   (default: all)
  scripts/run-ct-local.sh --help

Subcommands:
  dudect      Run the hand-rolled minimal dudect harness 20 consecutive
              times (5 sub-cases × 20 runs = 100 measurements). For each
              measurement, parses the `cuts=` line emitted by the harness,
              extracts MAX |t| across the 5 percentile cuts ([1.0, 0.95,
              0.99, 0.999, 0.9999]; cuts_field extraction logic), and
              asserts the sample_split_gate (|L-R|/(L+R) <= 5%; defence-
              in-depth per v2 Amendment 7 reframed for v3). ADVISORY-only
              per R24 v4 amendment (#r24-v4-amendment path (c)): reports
              MAX |t| transients for forensic visibility but does NOT
              block release. Cachegrind 312/312 zero counter delta +
              KernelDisass.html instruction-level proof + R25-01 memcheck-
              taint are the LOAD-BEARING gates. Wall-clock budget:
              ~40-60 min.

  cachegrind  Run valgrind --tool=cachegrind --branch-sim=yes on the
              expanded 16-class InputClass harness binary across 50 cells
              (32 mul + 18 inv) on x86_64. Then run 312 pairwise diffs
              (240 mul + 72 inv) per FIX_PLAN.html #r24-02 v3 LOCAL-ONLY.
              Acceptance gate (LOAD-BEARING): every pairwise diff has
              byte-identical kernel-row counters. Wall-clock budget:
              ~12-19 min. Requires valgrind >= 3.18
              (apt-get install valgrind).

  memcheck    Run TIMECOP-style memcheck-taint sweep (R25-01) — invoke
              valgrind --tool=memcheck on the memcheck_kernels harness for
              each of the 5 sub-cases × N=3 = 15 invocations on x86_64.
              The harness marks secret bytes as undefined via the
              VALGRIND_MAKE_MEM_UNDEFINED client request (hand-rolled
              inline-asm FFI macro); any branch / memory-address / store
              dependent on the tainted bytes triggers a memcheck warning.
              Acceptance gate (LOAD-BEARING per SD-R25-5): zero un-
              suppressed warnings across all 15 invocations =
              exit 0 (PASS). Suppressions for documented legitimate non-
              leak code live in valgrind/memcheck-suppressions.txt per
              MEDIUM-4 override-path procedure. Wall-clock budget:
              ~2-5 min. Requires valgrind >= 3.18.

  all         (default) Run cachegrind, dudect, then memcheck sequentially.
              Wall-clock budget: ~45-75 min total.

Output: per-subcommand logfile at /tmp/ct-local-<subcommand>-<timestamp>.log;
        one-line PASS summary on stdout for release-notes anchoring.

Exit codes (v4 amendment path (c) at FIX_PLAN.html #r24-v4-amendment;
SD-R25-5 LOAD-BEARING for memcheck):
  0 = LOAD-BEARING gates passed (cachegrind zero counter delta; memcheck
      zero un-suppressed warnings; dudect ADVISORY-only exit 0 regardless
      of |t|>=10 transients)
  1 = LOAD-BEARING gate failed (cachegrind non-zero counter delta;
      memcheck un-suppressed warning; sample-split breach; harness-
      internal NaN/inf/parse error)
  2 = invalid argument
  3 = prerequisites missing (valgrind absent for cachegrind or memcheck
      subcommand)

See FIX_PLAN.html #r24-plan + #r24-acceptance + #r24-v3-changelog +
#r24-v4-amendment + #r25-plan + #r25-01 for full rationale + the
release-discipline contract.
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

  echo "[2/3] Running dudect harness 20× across 5 sub-cases (100 measurements)..." \
      | tee -a "$logfile"

  local overall_max_abs="0.0"
  local fail_count=0
  local measurement_count=0

  # R26-01 v4 (path c, ADVISORY-only) probe-then-invoke for scheduling tools.
  # Probes taskset + nice ONCE at start of run_dudect; per-iteration
  # invocation runs ONCE. See FIX_PLAN.html #r26-01 + MED-1 fix.
  local pin_cmd=""
  local nice_cmd=""
  if command -v taskset >/dev/null 2>&1; then
    pin_cmd="taskset -c $(($(nproc) - 1))"
    echo "  pin: $pin_cmd (last core; lower IRQ load on stock Linux)" | tee -a "$logfile"
  else
    echo "  warn: taskset not available; running unpinned (ADVISORY signal less clean)" | tee -a "$logfile"
  fi
  if command -v nice >/dev/null 2>&1 && nice -n -10 true 2>/dev/null; then
    nice_cmd="nice -n -10"
    echo "  nice: $nice_cmd (probe succeeded)" | tee -a "$logfile"
  else
    echo "  warn: nice -n -10 probe failed (CAP_SYS_NICE absent or 'nice' not in PATH); running at default niceness (ADVISORY signal less clean)" | tee -a "$logfile"
  fi

  for run in {1..20}; do
    for sub in "${subcases[@]}"; do
      local raw
      raw=$($pin_cmd $nice_cmd "$binary" --kernel "$sub" 2>&1 | tee -a "$logfile")
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
      #
      # v4 amendment (M-1 fix): the regex was non-greedy
      # `sub(/[^=]*=/, ...)` which strips only the LEFTMOST `=` and
      # mis-parses the first cut's t-value as 1.0. Greedy `sub(/.*=/, ...)`
      # strips up to the LAST `=` so the numeric prefix is the t-value.
      local recomputed_max
      recomputed_max=$(echo "$cuts_field" | awk '
        BEGIN { max = 0 }
        {
          n = split($0, a, ",")
          for (i = 1; i <= n; i++) {
            v = a[i]
            sub(/.*=/, "", v)
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

      # v4 amendment: dudect is ADVISORY per architect+security joint-
      # surfaced path (c) maintainer-locked decision. Cachegrind 312/312
      # zero counter delta + KernelDisass.html instruction-level proof
      # are the LOAD-BEARING gates; dudect reports MAX |t| transients for
      # forensic visibility but does NOT block release. The R22 v2
      # Amendment 4 5/5-same-sub-case escalation ladder remains the
      # manual investigation procedure if a real CT leak ever surfaces.
      if awk -v t="$max_abs_field" 'BEGIN{ exit !(t < 0) }'; then
        # absolute value
        max_abs_field=$(awk -v t="$max_abs_field" 'BEGIN{ printf "%.5f", (t<0)?-t:t }')
      fi
      if awk -v t="$max_abs_field" 'BEGIN{ exit !(t >= 10.0) }'; then
        echo "  ADVISORY: transient |t|=$max_abs_field >=10 (run=$run sub=$sub) — host noise per R22 v2 Amendment 4 ladder; cachegrind+KernelDisass are LOAD-BEARING" \
            | tee -a "$logfile"
        fail_count=$((fail_count + 1))
      fi

      # Track overall max_abs across all measurements.
      overall_max_abs=$(awk -v cur="$overall_max_abs" -v new="$max_abs_field" \
          'BEGIN{ printf "%.5f", (new>cur)?new:cur }')
    done
  done

  echo "[3/3] Dudect discharge complete: $measurement_count measurements" \
      | tee -a "$logfile"
  if [ "$fail_count" -gt 0 ]; then
    echo "ADVISORY-with-transients: scripts/run-ct-local.sh dudect ($measurement_count measurements; $fail_count/100 transient(s) |t|>=10; overall MAX|t|=${overall_max_abs}; cachegrind 312/312 zero delta + KernelDisass.html are the LOAD-BEARING gates per R24 v4 amendment)" \
        | tee -a "$logfile"
    echo "  Per R22 v2 Amendment 4 escalation ladder (MANUAL investigation per R26-03 + maintainer-locked HIGH-1 (a)): 1-4/5 same-sub-case = host noise; 5/5 same-sub-case in any of the 16 sliding-window positions (runs 1-5, 2-6, ..., 16-20) = REAL leak requiring R-FIX. Transient breakdown logged above for manual investigation; the wrapper exits 0 ALWAYS — no programmatic 5-consecutive-runs scanner." \
        | tee -a "$logfile"
    return 0
  fi
  echo "ADVISORY: scripts/run-ct-local.sh dudect ($measurement_count measurements; overall MAX|t|=${overall_max_abs}; cachegrind 312/312 zero delta is the LOAD-BEARING gate per R24 v4 amendment)" \
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
          # v4 amendment (security M-2 / architect L-4 fix): parens around
          # `diff || true` so the diff content reaches the logfile on the
          # FAIL path. Without parens this parses as `diff || (true | tee)`
          # and the actual diff content is lost.
          (diff "$A" "$B" || true) | tee -a "$logfile"
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
# MEMCHECK subcommand (R25-01; LOAD-BEARING per SD-R25-5)
# ============================================================================
# TIMECOP-style memcheck-taint sweep: marks secret bytes as undefined via
# the VALGRIND_MAKE_MEM_UNDEFINED client request (hand-rolled inline-asm FFI
# macro in benches/memcheck_kernels.rs), then runs each sub-case under
# valgrind --tool=memcheck. Any "Conditional jump or move depends on
# uninitialised value(s)" warning or "Use of uninitialised value of size N"
# warning is a CT-leak signal pointing to the EXACT source line.
#
# LOAD-BEARING per SD-R25-5: the wrapper exits 1 on any un-suppressed
# warning; documented legitimate non-leak code (e.g., the inv() domain-
# error guard at src/legacy.rs:115) is suppressed via
# valgrind/memcheck-suppressions.txt per MEDIUM-4 override-path procedure.
#
# Probe-then-invoke pattern (mirror R26 MED-1 precedent): probe `command
# -v valgrind` at start; exit 3 (prerequisites-missing) if absent.
run_memcheck() {
  local logfile="/tmp/ct-local-memcheck-${TIMESTAMP}.log"
  echo "[R25-01 memcheck local discharge] log: ${logfile}"
  : > "$logfile"

  # Prerequisite check: valgrind must be installed (same exit code 3 as
  # the cachegrind subcommand for consistency).
  if ! command -v valgrind >/dev/null 2>&1; then
    echo "ERROR: valgrind not installed (apt-get install valgrind)" \
        | tee -a "$logfile" >&2
    return 3
  fi
  echo "  valgrind: $(valgrind --version)" | tee -a "$logfile"

  echo "[1/3] Building memcheck_kernels (bench profile, locked)..." \
      | tee -a "$logfile"
  ( cd "$REPO_ROOT" && cargo bench --no-run --bench memcheck_kernels --locked ) \
      2>&1 | tee -a "$logfile"

  local binary
  binary=$(locate_bench_binary memcheck_kernels) || return 3
  echo "  binary: $binary" | tee -a "$logfile"

  local SUPP="${REPO_ROOT}/valgrind/memcheck-suppressions.txt"
  if [ ! -f "$SUPP" ]; then
    echo "ERROR: suppressions file not found at $SUPP (MEDIUM-4 override- path file)" \
        | tee -a "$logfile" >&2
    return 1
  fi
  echo "  suppressions: $SUPP" | tee -a "$logfile"

  local subcases=(
    memcheck_mul_aes_zero
    memcheck_mul_aes_ff
    memcheck_mul_legacy_zero
    memcheck_mul_legacy_ff
    memcheck_inv_legacy_one
  )

  echo "[2/3] Running 5 sub-cases × N=3 = 15 memcheck-taint invocations \
(BINARY signal per MEDIUM-3)..." | tee -a "$logfile"

  local pass_count=0
  local fail_count=0
  local invocation_count=0
  # N=3 per sub-case for fail-loud robustness against transient PRNG-state
  # effects (MEDIUM-3 clarification; NOT a SAMPLES sweep).
  for sub in "${subcases[@]}"; do
    for iter in 1 2 3; do
      invocation_count=$((invocation_count + 1))
      echo "  invocation $invocation_count/15: kernel=$sub iter=$iter" \
          | tee -a "$logfile"
      # --error-exitcode=1 makes valgrind exit 1 on any un-suppressed error.
      # --suppressions=$SUPP applies the MEDIUM-4 override-path entries.
      # --track-origins=yes provides forensic detail when warnings surface.
      # --read-var-info=yes uses DWARF debuginfo for better attribution.
      # --leak-check=no skips the heap-leak summary (orthogonal to CT-taint).
      # --quiet suppresses the per-invocation startup banner (the warnings
      #   themselves still print on stderr).
      if valgrind --tool=memcheck \
                  --error-exitcode=1 \
                  --track-origins=yes \
                  --read-var-info=yes \
                  --leak-check=no \
                  --quiet \
                  --suppressions="$SUPP" \
                  "$binary" --kernel "$sub" 2>&1 | tee -a "$logfile"; then
        pass_count=$((pass_count + 1))
        echo "    [PASS] no un-suppressed memcheck warnings for $sub iter=$iter" \
            | tee -a "$logfile"
      else
        fail_count=$((fail_count + 1))
        echo "    [FAIL] memcheck warnings detected for $sub iter=$iter (see $logfile)" \
            | tee -a "$logfile" >&2
      fi
    done
  done

  echo "[3/3] Memcheck discharge complete: $invocation_count invocations \
($pass_count PASS / $fail_count FAIL)" | tee -a "$logfile"

  # LOAD-BEARING per SD-R25-5 planner default: non-zero exit on any FAIL.
  if [ "$fail_count" -gt 0 ]; then
    echo "FAIL: scripts/run-ct-local.sh memcheck ($fail_count of $invocation_count \
invocations surfaced un-suppressed memcheck warnings; see $logfile)" \
        | tee -a "$logfile" >&2
    echo "This indicates a data-dependent branch / address / store in a GF(2^8)" \
        "kernel — a REAL CT violation. Investigate before merging R25." \
        "Per MEDIUM-4 override-path procedure, legitimate non-leak code can be" \
        "suppressed via valgrind/memcheck-suppressions.txt with justification" \
        "+ date." | tee -a "$logfile" >&2
    return 1
  fi
  echo "PASS: scripts/run-ct-local.sh memcheck ($invocation_count invocations, \
zero taint violations)" | tee -a "$logfile"
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
    memcheck)
      run_memcheck
      ;;
    all)
      run_cachegrind || return $?
      run_dudect || return $?
      run_memcheck || return $?
      echo "PASS: scripts/run-ct-local.sh all (cachegrind LOAD-BEARING PASS + dudect ADVISORY exit 0 + memcheck LOAD-BEARING PASS; see per-subcommand lines above for transient counts, MAX|t| forensic detail per v4 amendment path (c), and per-invocation memcheck summary per SD-R25-5)"
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
