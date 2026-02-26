#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${1:-mcp-firewall:dev}"
OUT_DIR="dist"
SBOM_PATH="$OUT_DIR/sbom.cdx.json"

mkdir -p "$OUT_DIR"

if command -v cyclonedx-py >/dev/null 2>&1; then
  cyclonedx-py environment -o "$SBOM_PATH" --output-format JSON
elif command -v cyclonedx-bom >/dev/null 2>&1; then
  cyclonedx-bom -o "$SBOM_PATH"
else
  python3 - <<'PY'
import json, pkgutil
mods = sorted({m.name for m in pkgutil.iter_modules()})
sbom = {
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {"component": {"name": "mcp-firewall", "type": "application"}},
  "components": [{"type": "library", "name": m} for m in mods[:200]],
}
with open("dist/sbom.cdx.json", "w") as f:
    json.dump(sbom, f)
PY
fi

if command -v cosign >/dev/null 2>&1; then
  cosign attest --yes --predicate "$SBOM_PATH" --type cyclonedx "$IMAGE_REF"
else
  echo "[mcp-firewall] cosign not installed; skipping attestation" >&2
fi

echo "SBOM generated at $SBOM_PATH"
