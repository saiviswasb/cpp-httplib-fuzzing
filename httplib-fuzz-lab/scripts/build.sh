#!/usr/bin/env bash
# Build every fuzz target in three variants:
#   out/afl/<t>   AFL++ instrumented + ASan + UBSan   -> used for fuzzing
#   out/plain/<t> AFL++ instrumented, no sanitizers   -> used by afl-cmin
#   out/cov/<t>   clang source-based coverage         -> used to measure runs
#
# Usage: scripts/build.sh [target ...]   (default: all upstream targets)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/versions.env"

HTTPLIB="$ROOT/third_party/cpp-httplib"
UPSTREAM_FUZZ="$HTTPLIB/test/fuzzing"
OUT="$ROOT/out"
AFL_CXX="${AFL_CXX:-afl-clang-fast++}"
CXX="${CXX:-clang++-$LLVM_VERSION}"
command -v "$CXX" >/dev/null || CXX=clang++

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(server_fuzzer client_fuzzer header_parser_fuzzer
           url_parser_fuzzer multipart_parser_fuzzer)
fi

COMMON=(-std=c++17 -g -I"$HTTPLIB" -I"$UPSTREAM_FUZZ" -DCPPHTTPLIB_ZLIB_SUPPORT)
LIBS=(-lz -pthread)

mkdir -p "$OUT"/{afl,plain,cov}

src_for() {  # our own harnesses in harness/ take priority over upstream's
  if [[ -f "$ROOT/harness/$1.cc" ]]; then echo "$ROOT/harness/$1.cc"
  else echo "$UPSTREAM_FUZZ/$1.cc"; fi
}

for t in "${TARGETS[@]}"; do
  src="$(src_for "$t")"
  echo "[build] $t  <- ${src#$ROOT/}"

  # 1. Fuzzing build. -fsanitize=fuzzer makes afl-clang-fast link libAFLDriver,
  #    which supplies main() and calls LLVMFuzzerInitialize/TestOneInput.
  #    -fno-sanitize-recover makes UBSan abort, so AFL++ records it as a crash.
  AFL_QUIET=1 "$AFL_CXX" "${COMMON[@]}" -O1 \
      -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -fno-omit-frame-pointer \
      "$src" -o "$OUT/afl/$t" "${LIBS[@]}"

  # 2. Same instrumentation, no sanitizers: faster, used for afl-cmin.
  AFL_QUIET=1 "$AFL_CXX" "${COMMON[@]}" -O1 -fsanitize=fuzzer \
      "$src" -o "$OUT/plain/$t" "${LIBS[@]}"

  # 3. Coverage build: plain clang, no AFL instrumentation, our own runner.
  "$CXX" "${COMMON[@]}" -O0 -fprofile-instr-generate -fcoverage-mapping \
      "$src" "$ROOT/harness/cov_runner.cc" -o "$OUT/cov/$t" "${LIBS[@]}"
done
echo "[build] done -> $OUT"

# Build websocket_frame_fuzzer targets
$AFL_CXX $CXXFLAGS -Ithird_party/cpp-httplib harness/websocket_frame_fuzzer.cc -o out/afl/websocket_frame_fuzzer
$PLAIN_CXX $CXXFLAGS -Ithird_party/cpp-httplib harness/websocket_frame_fuzzer.cc -o out/plain/websocket_frame_fuzzer
$COV_CXX $CXXFLAGS -fprofile-instr-generate -fcoverage-mapping -Ithird_party/cpp-httplib harness/websocket_frame_fuzzer.cc harness/cov_runner.cc -o out/cov/websocket_frame_fuzzer
