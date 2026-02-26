# Getting Started

## Installation

```bash
pip install mcp-firewall
```

## Quick Start

### 1. Wrap any MCP server

```bash
mcp-firewall wrap -- npx @modelcontextprotocol/server-filesystem /tmp
```

That's it. mcp-firewall now intercepts every tool call, scans for threats, and enforces default security policies.

### 2. Generate a config

```bash
mcp-firewall init
```

This creates `mcp-firewall.yaml` with sensible defaults:
- Blocks SSH key access
- Blocks .env file access
- Requires approval for shell commands
- Allows file reads
- Rate limits at 200 calls/minute

### 3. Customize policies

Edit `mcp-firewall.yaml`:

```yaml
agents:
  claude-desktop:
    allow: [read_file, search]
    deny: [exec, shell, rm]
    rate_limit: "100/min"

rules:
  - name: block-credentials
    match:
      arguments:
        path: "**/.ssh/**"
    action: deny
```

### 4. Enable the dashboard

```bash
mcp-firewall wrap --dashboard -- python my_server.py
# Dashboard at http://127.0.0.1:9090
```

### 5. Use with Claude Desktop

Replace your MCP server config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home"]
    }
  }
}
```

### 6. Shared state for multiple MCP servers (recommended)

Start one shared daemon (with both Unix socket and TCP listeners):

```bash
mcp-firewall daemon --dashboard --listen-unix /tmp/mcp-firewall.sock --listen-tcp 127.0.0.1:9091
```

Then configure each MCP server to use `connect` with a stable `--server-id`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": ["connect", "--server-id", "filesystem", "--daemon-unix", "/tmp/mcp-firewall.sock", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home"]
    },
    "falcon-mcp": {
      "command": "mcp-firewall",
      "args": ["connect", "--server-id", "falcon-mcp", "--daemon-unix", "/tmp/mcp-firewall.sock", "--", "uvx", "--env-file", "/path/.env", "falcon-mcp"]
    }
  }
}
```

TCP connector variant:

```bash
mcp-firewall connect --server-id filesystem --daemon-unix '' --daemon-tcp 127.0.0.1:9091 -- npx -y @modelcontextprotocol/server-filesystem /home
```

## Features at a Glance

| Command | Description |
|---|---|
| `mcp-firewall wrap -- <server>` | Wrap and protect an MCP server |
| `mcp-firewall wrap --dashboard -- <server>` | With real-time dashboard |
| `mcp-firewall daemon` | Run shared firewall state for multiple MCP servers |
| `mcp-firewall connect --server-id <id> -- <server>` | Attach one MCP server session to shared daemon |
| `mcp-firewall init` | Generate starter config |
| `mcp-firewall validate` | Check config syntax |
| `mcp-firewall audit` | Verify audit log integrity |
| `mcp-firewall scan -- <server>` | Pre-deployment security scan |
| `mcp-firewall report dora` | DORA compliance report |
| `mcp-firewall report finma` | FINMA compliance report |
| `mcp-firewall report soc2` | SOC 2 evidence report |
| `mcp-firewall feed list` | List threat feed rules |

## Local Package Build and Install Check

Use this when validating release artifacts locally:

```bash
bash scripts/package_local.sh
bash scripts/test_local_install.sh
```

## Real MCP Wrap Validation

Validate the local wheel against a real MCP server wrapper flow:

```bash
bash tests/e2e/test_real_mcp_wrap.sh
```

## Next Steps

- [Policy Reference](policies.md) — Full policy configuration guide
- [Compliance Guide](compliance.md) — Regulatory report generation
- [Threat Feed](threat-feed.md) — Community detection rules
- [Architecture](../ARCHITECTURE.md) — Technical deep dive
