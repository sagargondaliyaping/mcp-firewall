#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${1:-mcp-firewall:dev}"
SBOM_PATH="dist/sbom.cdx.json"

if [[ ! -f "$SBOM_PATH" ]]; then
  echo "SBOM missing: $SBOM_PATH" >&2
  exit 1
fi

if command -v cosign >/dev/null 2>&1; then
  cosign verify-attestation "$IMAGE_REF" --type cyclonedx >/dev/null
  echo "Attestation verified for $IMAGE_REF"
else
  echo "[mcp-firewall] cosign not installed; verified local SBOM artifact only" >&2
fi
