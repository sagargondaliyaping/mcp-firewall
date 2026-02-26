# Release Integrity Controls

This project publishes release-security artifacts to support software supply-chain assurance.

## Controls

- SBOM generation in CycloneDX format (`dist/sbom.cdx.json`)
- Optional cosign attestation generation
- Optional cosign attestation verification
- CI workflow guard to ensure SBOM artifact exists

## Local commands

```bash
bash scripts/generate_sbom.sh mcp-firewall:dev
bash scripts/verify_attestation.sh mcp-firewall:dev
```

## CI workflow

The GitHub Actions workflow `.github/workflows/release-security.yml` executes:

1. SBOM generation
2. SBOM file existence check
3. Attestation verification step

If `cosign` is unavailable, scripts still enforce SBOM artifact generation and log a warning.
