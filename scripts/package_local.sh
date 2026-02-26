#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dist

if python3 -m build --version >/dev/null 2>&1; then
  python3 -m build
else
  if python3 -m pip install --upgrade build >/dev/null 2>&1; then
    python3 -m build
  else
    echo "python -m build unavailable; using offline wheel fallback."
    python3 -m pip wheel . --no-deps --no-build-isolation -w dist
  fi
fi

echo "Built distributions in $ROOT_DIR/dist"
