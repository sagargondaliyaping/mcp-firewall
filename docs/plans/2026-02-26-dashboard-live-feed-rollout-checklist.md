# Dashboard Live Feed Rollout Checklist

Date: 2026-02-26
Owner: Security Engineering

## Packaging and Install Validation

- [ ] `bash scripts/package_local.sh`
- [ ] `bash scripts/test_local_install.sh`
- [ ] Confirm `mcp-firewall --version` from the clean venv

## Real MCP Wrapping Validation

- [ ] `bash tests/e2e/test_real_mcp_wrap.sh`
- [ ] Confirm output includes `PASS: real MCP wrapping flow produced firewall decision output.`

## Dashboard Event Validation

- [ ] Start wrapped server with dashboard enabled
- [ ] Trigger inbound deny for cloud metadata URL
- [ ] Confirm event includes: hostname, stage, findings, correlation_id, control_id/rule_name keys
- [ ] Verify `/api/events` filtering by action/severity/agent/tool/stage

## Regression Validation

- [ ] `python3 -m pytest -q`
- [ ] `python3 -m pytest tests/security/test_standards_regression.py -v`
