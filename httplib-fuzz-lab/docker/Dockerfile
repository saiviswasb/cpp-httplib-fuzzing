# Reproducible fuzzing environment for cpp-httplib.
# Same toolchain that produced every result in results/: Ubuntu 24.04,
# LLVM/clang 18, AFL++ v4.32c built from source.
#
# Build:  docker build -t httplib-fuzz -f docker/Dockerfile .
# Run:    docker run --rm -it -v "$PWD":/work httplib-fuzz
FROM ubuntu:24.04

ARG AFLPP_TAG=v4.32c
ARG LLVM_VERSION=18
ENV DEBIAN_FRONTEND=noninteractive

# clang/lld/llvm-dev: compiler + the LLVM libraries AFL++'s passes link against
# libclang-rt-dev:    ASan/UBSan/libFuzzer runtimes (not installed by default)
# lcov:               HTML coverage reports; python3: plotting scripts
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git make build-essential python3 python3-pip \
      clang-${LLVM_VERSION} lld-${LLVM_VERSION} llvm-${LLVM_VERSION} \
      llvm-${LLVM_VERSION}-dev libclang-rt-${LLVM_VERSION}-dev \
      zlib1g-dev lcov tmux zip \
    && rm -rf /var/lib/apt/lists/*

# Build AFL++ from a pinned tag. QEMU/Nyx/Unicorn modes are for binary-only
# targets; we compile from source, so we skip them. The optional GCC-plugin
# mode fails to build without gcc-plugin-dev; that is expected and harmless.
RUN git clone --depth 1 --branch ${AFLPP_TAG} \
      https://github.com/AFLplusplus/AFLplusplus.git /opt/aflpp \
 && cd /opt/aflpp \
 && LLVM_CONFIG=llvm-config-${LLVM_VERSION} make -j"$(nproc)" source-only \
      NO_NYX=1 NO_QEMU=1 NO_UNICORN_ARM64=1 \
 && make install \
 && test -x /usr/local/bin/afl-fuzz && test -x /usr/local/bin/afl-clang-fast++

ENV CXX=clang++-${LLVM_VERSION} \
    AFL_SKIP_CPUFREQ=1
WORKDIR /work
CMD ["bash"]
