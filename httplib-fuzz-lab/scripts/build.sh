#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="/work/out"
mkdir -p "${OUT_DIR}/afl" "${OUT_DIR}/plain" "${OUT_DIR}/cov"

AFL_CXX=${AFL_CXX:-afl-clang-fast++}
PLAIN_CXX=${PLAIN_CXX:-clang++-18}
COV_CXX=${COV_CXX:-clang++-18}
CXXFLAGS="${CXXFLAGS:- -O2 -g -std=c++17}"

TARGETS=(
  "server_fuzzer"
  "client_fuzzer"
  "header_parser_fuzzer"
  "url_parser_fuzzer"
  "multipart_parser_fuzzer"
  "websocket_frame_fuzzer"
  "chunked_decoder_fuzzer"
)

for target in "${TARGETS[@]}"; do
  if [ -f "harness/${target}.cc" ]; then
    SRC="harness/${target}.cc"
  else
    SRC="third_party/cpp-httplib/test/fuzzing/${target}.cc"
  fi

  echo "[build] ${target} <- ${SRC}"
  $AFL_CXX $CXXFLAGS -Ithird_party/cpp-httplib "${SRC}" harness/cov_runner.cc -o "${OUT_DIR}/afl/${target}"
  $PLAIN_CXX $CXXFLAGS -Ithird_party/cpp-httplib "${SRC}" harness/cov_runner.cc -o "${OUT_DIR}/plain/${target}"
  $COV_CXX $CXXFLAGS -fprofile-instr-generate -fcoverage-mapping -Ithird_party/cpp-httplib "${SRC}" harness/cov_runner.cc -o "${OUT_DIR}/cov/${target}"
done

echo "[build] done -> ${OUT_DIR}"
