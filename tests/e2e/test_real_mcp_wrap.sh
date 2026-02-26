#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }
command -v npx >/dev/null 2>&1 || { echo "npx is required"; exit 1; }

if ! ls dist/mcp_firewall-*.whl >/dev/null 2>&1; then
  bash scripts/package_local.sh
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 -m venv "$TMP_DIR/venv"
# shellcheck disable=SC1091
source "$TMP_DIR/venv/bin/activate"
python -m pip install --upgrade pip >/dev/null
WHEEL="$(ls -1 dist/mcp_firewall-*.whl | sort | tail -n 1)"
pip install "$WHEEL" >/dev/null

python - <<'PY'
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path.cwd()
tmp = pathlib.Path(os.environ.get("TMPDIR", "/tmp"))
workspace = pathlib.Path(str(tmp)) / "mcp-firewall-real-wrap"
workspace.mkdir(parents=True, exist_ok=True)

request = {
    "jsonrpc": "2.0",
    "id": "real-wrap-1",
    "method": "tools/call",
    "params": {
        "name": "fetch",
        "arguments": {"url": "http://169.254.169.254/latest/meta-data"},
    },
}

cmd = [
    "mcp-firewall",
    "wrap",
    "--",
    "npx",
    "-y",
    "@modelcontextprotocol/server-filesystem",
    str(workspace),
]

proc = subprocess.Popen(
    cmd,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

assert proc.stdin is not None
proc.stdin.write(json.dumps(request) + "\n")
proc.stdin.flush()
proc.stdin.close()

try:
    out, err = proc.communicate(timeout=25)
except subprocess.TimeoutExpired:
    proc.kill()
    out, err = proc.communicate()
    print("Timed out waiting for wrapped server output.")
    print("STDOUT:", out)
    print("STDERR:", err)
    sys.exit(1)

combined = out + "\n" + err
if "[mcp-firewall] Blocked:" not in combined:
    print("Expected firewall block marker not found.")
    print("STDOUT:", out)
    print("STDERR:", err)
    sys.exit(1)

print("PASS: real MCP wrapping flow produced firewall decision output.")
PY
