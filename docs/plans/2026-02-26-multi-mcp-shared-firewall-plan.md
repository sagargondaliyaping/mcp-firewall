# Multi-MCP Shared Firewall Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add shared-state multi-MCP support via daemon/connect commands while preserving existing wrap mode.

**Architecture:** Introduce a central daemon that owns shared policy/dashboard/audit state and serves per-server connector sessions over Unix socket and TCP. Connector command relays stdio traffic and session metadata. Dashboard events gain `server_id` to support shared multi-server visibility and filtering.

**Tech Stack:** Python 3.11+, asyncio streams, FastAPI dashboard, Click CLI, pytest.

---

### Task 1: Extend event schema for multi-server identity

**Files:**
- Modify: `mcp_firewall/models.py`
- Modify: `mcp_firewall/dashboard/events.py`
- Test: `tests/test_phase3.py`

**Step 1: Write failing test**
- Add test asserting `build_dashboard_event(..., server_id="filesystem")` includes `server_id`.

**Step 2: Verify RED**
Run: `python3 -m pytest tests/test_phase3.py::test_dashboard_event_schema_includes_server_id -v`

**Step 3: Minimal implementation**
- Add `server_id` to `DashboardEvent` model.
- Add optional `server_id` arg to `build_dashboard_event` defaulting to `"default"`.

**Step 4: Verify GREEN**
Run same command, expect PASS.

### Task 2: Add dashboard filtering by server_id

**Files:**
- Modify: `mcp_firewall/dashboard/app.py`
- Modify: `tests/test_phase3.py`

**Step 1: Write failing test**
- Add `/api/events?...&server_id=filesystem` filter test.

**Step 2: Verify RED**
Run: `python3 -m pytest tests/test_phase3.py::TestDashboardAPI::test_events_endpoint_supports_server_id_filter -v`

**Step 3: Minimal implementation**
- Add optional `server_id` query param and filter logic.
- Add server id render chip in feed row.

**Step 4: Verify GREEN**
Run same command, expect PASS.

### Task 3: Implement shared daemon runtime and connector protocol

**Files:**
- Create: `mcp_firewall/proxy/shared_daemon.py`
- Modify: `mcp_firewall/cli.py`
- Test: `tests/test_shared_daemon.py`

**Step 1: Write failing tests**
- Add test that daemon handles connector handshake and denies metadata fetch with shared pipeline.
- Add test that connector helper sends handshake with server_id.

**Step 2: Verify RED**
Run: `python3 -m pytest tests/test_shared_daemon.py -v`

**Step 3: Minimal implementation**
- Add daemon class with Unix/TCP listeners.
- Add per-session backend subprocess proxying with shared runner + dashboard event emission.
- Add `daemon` and `connect` CLI commands.

**Step 4: Verify GREEN**
Run: `python3 -m pytest tests/test_shared_daemon.py -v`

### Task 4: Route event emission through server-aware metadata

**Files:**
- Modify: `mcp_firewall/proxy/stdio.py`
- Modify: `mcp_firewall/proxy/shared_daemon.py`
- Modify: `tests/test_milestone_a.py`

**Step 1: Write failing test**
- Ensure deny events include `server_id` when session metadata exists.

**Step 2: Verify RED**
Run: `python3 -m pytest tests/test_milestone_a.py::test_deny_event_contains_server_id -v`

**Step 3: Minimal implementation**
- Plumb `server_id` through event builder calls.

**Step 4: Verify GREEN**
Run same command.

### Task 5: Update docs with multi-MCP shared-state config

**Files:**
- Modify: `docs/getting-started.md`
- Modify: `README.md`

**Step 1: Add docs**
- Add daemon startup examples for Unix and TCP.
- Add client config example using per-server `connect` entries.

**Step 2: Verify**
Run: `python3 -m pytest tests/test_phase3.py tests/test_shared_daemon.py -q`

### Task 6: Full regression

**Step 1:** Run `python3 -m pytest -q`
**Step 2:** Run `bash tests/e2e/test_real_mcp_wrap.sh`
