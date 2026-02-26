# Security Scorecard

## Coverage Targets

- Baseline control coverage target: **>= 80% implemented**
- Runtime enforcement target for P0 controls: **100%**
- Audit evidence freshness target: **<= 30 days**

## Current Status

- Baseline coverage: **100% (9/9 controls implemented)**
- P0 runtime controls: **Implemented**
- Evidence artifacts:
  - `docs/security/standards-mapping.csv`
  - `docs/security/control-catalog.md`
  - `mcp-firewall.audit.jsonl` (runtime)

## Review Cadence

- Update scorecard on every milestone completion.
- Re-run `tests/security/test_standards_regression.py` in CI and before release.
