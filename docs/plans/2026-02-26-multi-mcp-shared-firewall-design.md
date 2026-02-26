# Multi-MCP Shared Firewall Design

## Goal
Enable `mcp-firewall` to protect multiple MCP servers with one shared firewall state, one dashboard, and one policy/audit pipeline.

## Problem
Current `wrap --dashboard` runs per MCP server process. In multi-server client configs, each process competes for dashboard port and keeps isolated memory state.

## Design
- Add a central `mcp-firewall daemon` process that owns shared runtime state.
- Add `mcp-firewall connect` command for each MCP server entry in client configs.
- Each `connect` process opens a session to daemon (Unix socket and/or TCP), sends server metadata + backend command, then streams JSON-RPC bytes.
- Daemon spawns/owns backend MCP subprocess per connection and applies existing inbound/outbound pipeline with shared dashboard and audit state.
- Extend event schema with `server_id` and expose dashboard filter by `server_id`.

## Compatibility
- Keep `wrap` command for single-server mode.
- `connect` is the recommended mode for multiple MCP servers with shared state.

## Security and Ops
- Support both listeners:
  - Unix socket for local host-only operation.
  - TCP (`127.0.0.1:<port>`) as fallback.
- Handshake requires `server_id` and backend command; no remote auth in this iteration (local-only expectation).

## Testing Strategy
- TDD for event schema + API filtering + daemon/connect transport behavior.
- Regression suite must pass.
