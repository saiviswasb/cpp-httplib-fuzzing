#!/usr/bin/env bash
# Clone cpp-httplib at the pinned commit into third_party/cpp-httplib.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/versions.env"

DEST="$ROOT/third_party/cpp-httplib"
if [[ ! -d "$DEST/.git" ]]; then
  git clone --quiet "$HTTPLIB_REPO" "$DEST"
fi
git -C "$DEST" fetch --quiet origin "$HTTPLIB_COMMIT" || true
git -C "$DEST" checkout --quiet "$HTTPLIB_COMMIT"
echo "[fetch] cpp-httplib at $(git -C "$DEST" rev-parse --short HEAD)"
