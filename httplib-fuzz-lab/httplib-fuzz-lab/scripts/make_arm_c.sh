#!/usr/bin/env bash
# Build Arm C for a target: (Arm A seeds + Arm B seeds), minimized with afl-cmin,
# and the union of both dictionaries.
#
# afl-cmin runs every seed through the instrumented binary and keeps the
# smallest set of files that still hits every edge any seed hit. That only
# works if the binary actually receives input, so it uses out/plain/<target>
# (no sanitizers: faster, same edges) and refuses a binary without the driver.
#
# Usage: scripts/make_arm_c.sh <target>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="${1:?usage: make_arm_c.sh <target>}"
A="$ROOT/corpora/$T/A"; B="$ROOT/corpora/$T/B"; C="$ROOT/corpora/$T/C"
BIN="$ROOT/out/plain/$T"

[[ -d "$A" && -d "$B" ]] || { echo "need corpora/$T/A and corpora/$T/B"; exit 1; }
grep -qa '##SIG_AFL_PERSISTENT##' "$BIN" || {
  echo "FATAL: $BIN has no AFL++ driver; run scripts/build.sh first"; exit 1; }

# Work dir inside the repo: afl-cmin warns against /tmp for security reasons.
TMP="$(mktemp -d "$ROOT/results/.armc.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/union"
# Prefix names so A/x and B/x do not overwrite each other.
for f in "$A"/*; do [[ -f "$f" ]] && cp "$f" "$TMP/union/A_$(basename "$f")"; done
for f in "$B"/*; do [[ -f "$f" ]] && cp "$f" "$TMP/union/B_$(basename "$f")"; done

rm -rf "$C"
# @@ = pass each seed as a file argument. The libAFLDriver binary only reads
# from shared memory (inside afl-fuzz) or from a file; on stdin it waits, and
# afl-cmin then reports "no instrumentation output".
AFL_NO_UI=1 afl-cmin -i "$TMP/union" -o "$C" -- "$BIN" @@ > "$TMP/cmin.log" 2>&1 || {
  cat "$TMP/cmin.log"; exit 1; }
grep -E 'Found|Narrowed|tuples' "$TMP/cmin.log" || true

# Dictionary C = A + B, duplicates removed, comments and blank lines dropped.
mkdir -p "$ROOT/dicts/$T"
cat "$ROOT/dicts/$T/A.dict" "$ROOT/dicts/$T/B.dict" 2>/dev/null \
  | grep -vE '^\s*(#|$)' | sort -u > "$ROOT/dicts/$T/C.dict" || true

echo "[arm C] $T: $(ls "$A" | wc -l) A + $(ls "$B" | wc -l) B seeds -> $(ls "$C" | wc -l) kept;" \
     "dict entries: $(wc -l < "$ROOT/dicts/$T/C.dict")"
