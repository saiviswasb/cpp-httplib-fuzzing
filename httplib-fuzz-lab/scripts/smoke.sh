#!/usr/bin/env bash
# Day-one go/no-go check: fuzz a target briefly and confirm that
#  (a) AFL++ starts and sees instrumentation,
#  (b) the corpus grows (new paths are being found),
#  (c) the coverage build replays the queue and llvm-cov reports httplib.h.
# Usage: scripts/smoke.sh [target] [seconds]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/versions.env"
T="${1:-server_fuzzer}"
SECS="${2:-60}"
SEEDS="$ROOT/third_party/cpp-httplib/test/fuzzing/corpus"
DICT="$ROOT/third_party/cpp-httplib/test/fuzzing/server_fuzzer.dict"
WORK="$ROOT/results/smoke/$T"
rm -rf "$WORK"; mkdir -p "$WORK"

PROFDATA="llvm-profdata-$LLVM_VERSION"; command -v "$PROFDATA" >/dev/null || PROFDATA=llvm-profdata
LLVMCOV="llvm-cov-$LLVM_VERSION";       command -v "$LLVMCOV"  >/dev/null || LLVMCOV=llvm-cov

echo "[smoke] fuzzing $T for ${SECS}s"
AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  timeout --preserve-status "$((SECS + 15))" \
  afl-fuzz -V "$SECS" -i "$SEEDS" -o "$WORK/afl" -x "$DICT" -- "$ROOT/out/afl/$T" \
  > "$WORK/afl.log" 2>&1 || true

STATS="$WORK/afl/default/fuzzer_stats"
[[ -f "$STATS" ]] || { echo "[smoke] FAIL: afl-fuzz did not start"; tail -30 "$WORK/afl.log"; exit 1; }
grep -E '^(execs_done|execs_per_sec|corpus_count|corpus_found|saved_crashes|bitmap_cvg)' "$STATS"

echo "[smoke] replaying queue through coverage build"
LLVM_PROFILE_FILE="$WORK/cov.profraw" "$ROOT/out/cov/$T" "$WORK/afl/default/queue"
"$PROFDATA" merge -sparse "$WORK/cov.profraw" -o "$WORK/cov.profdata"
"$LLVMCOV" report "$ROOT/out/cov/$T" -instr-profile="$WORK/cov.profdata" \
  "$ROOT/third_party/cpp-httplib/httplib.h" | tail -1 | tee "$WORK/coverage.txt"

found=$(awk -F: '/^corpus_found/{gsub(/ /,"",$2);print $2}' "$STATS")
if [[ "${found:-0}" -gt 0 ]]; then echo "[smoke] GO: $found new inputs found"
else echo "[smoke] NO-GO: no new coverage found"; exit 1; fi
