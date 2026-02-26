# Dashboard Live Feed and Packaging Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade the dashboard to provide richer, security-useful live telemetry (including hostname and structured findings), then produce a local pip-installable package and validate it against a real MCP server.

**Architecture:** Keep the current in-process dashboard model (`dashboard_state`) but introduce a normalized event schema shared across proxy, pipeline, and dashboard APIs. Extend feed rendering with structured finding chips and drill-down payloads. Package with wheel/sdist and validate using an actual wrapped MCP server in an isolated venv.

**Tech Stack:** Python 3.11+, FastAPI/WebSocket, Pydantic models, pytest, setuptools build backend, pip, MCP stdio transport.

---

### Task 1: Define a normalized dashboard event schema with hostname + findings

**Files:**
- Create: `mcp_firewall/dashboard/events.py`
- Modify: `mcp_firewall/models.py`
- Test: `tests/test_phase3.py`

**Step 1: Write the failing test**

```python
# tests/test_phase3.py

def test_dashboard_event_schema_includes_hostname_and_findings():
    from mcp_firewall.dashboard.events import build_dashboard_event

    evt = build_dashboard_event(
        action="deny",
        tool="fetch",
        severity="high",
        reason="Cloud metadata endpoint blocked",
        findings=[{"type": "egress", "matched": "169.254.169.254"}],
    )
    assert "hostname" in evt
    assert "findings" in evt
```

**Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_phase3.py::test_dashboard_event_schema_includes_hostname_and_findings -v`
Expected: FAIL (module/function missing).

**Step 3: Write minimal implementation**

```python
# mcp_firewall/dashboard/events.py
# build_dashboard_event(...): returns dict with hostname, correlation_id, control_id, rule_name, findings
```

**Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_phase3.py::test_dashboard_event_schema_includes_hostname_and_findings -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add mcp_firewall/dashboard/events.py mcp_firewall/models.py tests/test_phase3.py
git commit -m "feat: add normalized dashboard event schema with hostname and findings"
```

### Task 2: Emit enriched inbound and outbound events from proxy/pipeline

**Files:**
- Modify: `mcp_firewall/proxy/stdio.py`
- Modify: `mcp_firewall/pipeline/runner.py`
- Modify: `mcp_firewall/pipeline/inbound/*.py` (only where details needed)
- Modify: `mcp_firewall/pipeline/outbound/*.py`
- Test: `tests/test_milestone_a.py`, `tests/test_milestone_b.py`

**Step 1: Write the failing test**

```python
# tests/test_milestone_a.py

def test_deny_event_contains_hostname_stage_and_findings():
    # trigger inbound deny and assert event payload includes:
    # hostname, stage, reason, findings[], control_id/rule_name when present
    assert False
```

**Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_milestone_a.py::test_deny_event_contains_hostname_stage_and_findings -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# stdio.py
# replace ad-hoc add_event dicts with build_dashboard_event(...)
# include outbound decisions (redact/deny) as dashboard events too
```

**Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_milestone_a.py::test_deny_event_contains_hostname_stage_and_findings -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add mcp_firewall/proxy/stdio.py mcp_firewall/pipeline/runner.py mcp_firewall/pipeline/inbound mcp_firewall/pipeline/outbound tests/test_milestone_a.py tests/test_milestone_b.py
git commit -m "feat: emit enriched dashboard events for inbound and outbound decisions"
```

### Task 3: Expand dashboard API for filtering and richer event retrieval

**Files:**
- Modify: `mcp_firewall/dashboard/app.py`
- Test: `tests/test_phase3.py`

**Step 1: Write the failing test**

```python
# tests/test_phase3.py

def test_events_endpoint_supports_filters():
    # /api/events?limit=50&action=deny&severity=high&agent=claude&tool=fetch
    assert filtered_count >= 0
```

**Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_phase3.py::test_events_endpoint_supports_filters -v`
Expected: FAIL (filters unsupported).

**Step 3: Write minimal implementation**

```python
# app.py
# /api/events accepts action,severity,agent,tool,stage,time_from,time_to
# returns filtered subset + total_count metadata
```

**Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_phase3.py::test_events_endpoint_supports_filters -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add mcp_firewall/dashboard/app.py tests/test_phase3.py
git commit -m "feat: add dashboard event filtering API"
```

### Task 4: Improve dashboard UI live feed with security details

**Files:**
- Modify: `mcp_firewall/dashboard/app.py` (embedded HTML/CSS/JS)
- Test: `tests/test_phase3.py`

**Step 1: Write the failing test**

```python
# tests/test_phase3.py

def test_dashboard_html_contains_finding_and_hostname_columns():
    from mcp_firewall.dashboard.app import DASHBOARD_HTML
    assert "Hostname" in DASHBOARD_HTML
    assert "Findings" in DASHBOARD_HTML
```

**Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_phase3.py::test_dashboard_html_contains_finding_and_hostname_columns -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```html
<!-- add columns/chips/details drawer for findings, hostname, control_id, rule_name -->
```

**Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_phase3.py::test_dashboard_html_contains_finding_and_hostname_columns -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add mcp_firewall/dashboard/app.py tests/test_phase3.py
git commit -m "feat: improve dashboard live feed with hostname and finding details"
```

### Task 5: Add end-to-end dashboard event contract tests

**Files:**
- Create: `tests/test_dashboard_event_contract.py`
- Modify: `tests/test_phase3.py`

**Step 1: Write the failing test**

```python
# tests/test_dashboard_event_contract.py

def test_inbound_deny_event_contract_complete():
    # assert required keys present and types stable
    assert event["hostname"]
    assert isinstance(event["findings"], list)
```

**Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_dashboard_event_contract.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
# align event builder and emitters with contract
```

**Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_dashboard_event_contract.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/test_dashboard_event_contract.py tests/test_phase3.py mcp_firewall/dashboard mcp_firewall/proxy/stdio.py
git commit -m "test: add dashboard event contract coverage"
```

### Task 6: Add packaging helper and local install validation script

**Files:**
- Create: `scripts/package_local.sh`
- Create: `scripts/test_local_install.sh`
- Modify: `README.md`
- Modify: `docs/getting-started.md`

**Step 1: Write the failing test**

```bash
# shell check style gate
bash -n scripts/package_local.sh scripts/test_local_install.sh
```

**Step 2: Run test to verify it fails**

Run: `bash -n scripts/package_local.sh`
Expected: FAIL (files missing).

**Step 3: Write minimal implementation**

```bash
# package_local.sh
python3 -m pip install --upgrade build
python3 -m build

# test_local_install.sh
python3 -m venv .venv-local-pkg
source .venv-local-pkg/bin/activate
pip install dist/mcp_firewall-*.whl
mcp-firewall --version
```

**Step 4: Run test to verify it passes**

Run: `bash -n scripts/package_local.sh scripts/test_local_install.sh`
Expected: PASS.

**Step 5: Commit**

```bash
git add scripts/package_local.sh scripts/test_local_install.sh README.md docs/getting-started.md
git commit -m "build: add local package build and install validation scripts"
```

### Task 7: Validate packaged install against a real MCP server

**Files:**
- Create: `tests/e2e/test_real_mcp_wrap.sh`
- Modify: `docs/getting-started.md`
- Modify: `docs/use-cases.md`

**Step 1: Write the failing test**

```bash
# tests/e2e/test_real_mcp_wrap.sh should fail until implemented
```

**Step 2: Run test to verify it fails**

Run: `bash tests/e2e/test_real_mcp_wrap.sh`
Expected: FAIL (script missing or checks not implemented).

**Step 3: Write minimal implementation**

```bash
# test_real_mcp_wrap.sh
# 1) build wheel
# 2) install in temp venv
# 3) run: mcp-firewall wrap -- npx @modelcontextprotocol/server-filesystem /tmp
# 4) send sample JSON-RPC tools/call over stdio
# 5) assert firewall decision present in output
```

**Step 4: Run test to verify it passes**

Run: `bash tests/e2e/test_real_mcp_wrap.sh`
Expected: PASS with clear output.

**Step 5: Commit**

```bash
git add tests/e2e/test_real_mcp_wrap.sh docs/getting-started.md docs/use-cases.md
git commit -m "test: validate local wheel against real MCP server wrapping flow"
```

### Task 8: Final regression and release-ready checklist

**Files:**
- Modify: `docs/security/security-scorecard.md`
- Create: `docs/plans/2026-02-26-dashboard-live-feed-rollout-checklist.md`

**Step 1: Write the failing test**

```python
# optional: add checklist existence test
assert Path("docs/plans/2026-02-26-dashboard-live-feed-rollout-checklist.md").exists()
```

**Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/security/test_standards_regression.py -v`
Expected: FAIL if checklist/coverage reference missing.

**Step 3: Write minimal implementation**

```markdown
# rollout checklist with: package build, install, real MCP wrap, dashboard feed validation
```

**Step 4: Run test to verify it passes**

Run:
- `python3 -m pytest -q`
- `bash scripts/package_local.sh`
- `bash scripts/test_local_install.sh`
- `bash tests/e2e/test_real_mcp_wrap.sh`
Expected: all pass.

**Step 5: Commit**

```bash
git add docs/security/security-scorecard.md docs/plans/2026-02-26-dashboard-live-feed-rollout-checklist.md
git commit -m "docs: add dashboard rollout and package validation checklist"
```

## Suggested Useful Live-Feed Fields (to include in events)

- `hostname` (system host running firewall)
- `target_hostname` (parsed from URL/path arguments when applicable)
- `correlation_id` (request/tool call ID)
- `agent`, `tool`, `stage`, `action`, `severity`, `reason`
- `control_id`, `rule_name`
- `findings[]` with structured items: `type`, `matched`, `confidence`, `action`
- `latency_ms`
- `timestamp`

## Real MCP validation prerequisites

- Node.js + npm installed (for `npx @modelcontextprotocol/server-filesystem`)
- Python build tools installed (`build`, `pip`, `venv`)
- Optional: `jq` for shell assertions

## Acceptance criteria

- Dashboard live feed shows hostname and structured findings for deny/redact/prompt events.
- `/api/events` supports filterable retrieval for incident triage.
- Wheel install works in clean venv and `mcp-firewall --version` succeeds.
- Real MCP wrap test executes and confirms firewall interception behavior.
- Full automated test suite passes.
