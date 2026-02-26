#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! ls dist/mcp_firewall-*.whl >/dev/null 2>&1; then
  echo "No wheel found in dist/. Run scripts/package_local.sh first."
  exit 1
fi

VENV_DIR=".venv-local-pkg"
python3 -m venv "$VENV_DIR"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip

WHEEL="$(ls -1 dist/mcp_firewall-*.whl | sort | tail -n 1)"
pip install "$WHEEL"
mcp-firewall --version
