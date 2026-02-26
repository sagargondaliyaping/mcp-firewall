# Security Scorecard

## Coverage Targets

- Baseline control coverage target: **>= 80% implemented**
- Runtime enforcement target for P0 controls: **100%**
- Audit evidence freshness target: **<= 30 days**

## Current Status

- Baseline coverage: **100% (9/9 controls implemented)**
- P0 runtime controls: **Implemented**
- Dashboard live-feed contract: **Implemented** (hostname + findings + filtered events API)
- Local package validation scripts: **Implemented** (`scripts/package_local.sh`, `scripts/test_local_install.sh`)
- Real MCP wrap validation: **Implemented** (`tests/e2e/test_real_mcp_wrap.sh`)
- Evidence artifacts:
  - `docs/security/standards-mapping.csv`
  - `docs/security/control-catalog.md`
  - `docs/plans/2026-02-26-dashboard-live-feed-rollout-checklist.md`
  - `mcp-firewall.audit.jsonl` (runtime)

## Review Cadence

- Update scorecard on every milestone completion.
- Re-run `tests/security/test_standards_regression.py` in CI and before release.
