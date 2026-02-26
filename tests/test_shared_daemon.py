"""Tests for shared multi-MCP daemon/connect mode."""

from __future__ import annotations

from click.testing import CliRunner

from mcp_firewall.cli import main


def test_cli_exposes_daemon_and_connect_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "daemon" in result.output
    assert "connect" in result.output


def test_connect_handshake_contains_server_identity() -> None:
    from mcp_firewall.proxy.shared_daemon import build_connect_handshake

    payload = build_connect_handshake("filesystem", ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"])
    assert payload["type"] == "connect"
    assert payload["server_id"] == "filesystem"
    assert payload["server_command"][0] == "npx"


def test_shared_daemon_uses_noninteractive_human_approval() -> None:
    from mcp_firewall.models import GatewayConfig
    from mcp_firewall.proxy.shared_daemon import SharedFirewallDaemon

    daemon = SharedFirewallDaemon(GatewayConfig())
    assert daemon.pipeline._approval._auto_approve is True
