"""Dashboard event contract tests."""

from __future__ import annotations

import asyncio
import io
import json
from types import SimpleNamespace

from rich.console import Console

from mcp_firewall.dashboard.app import DashboardState
from mcp_firewall.models import Action, GatewayConfig
from mcp_firewall.proxy import stdio as stdio_module


def test_inbound_deny_event_contract_complete(monkeypatch) -> None:
    config = GatewayConfig(default_action=Action.ALLOW)
    config.audit.enabled = False
    proxy = stdio_module.StdioProxy(config, console=Console(file=io.StringIO()))

    test_state = DashboardState()
    monkeypatch.setattr(stdio_module, "dashboard_state", test_state)
    monkeypatch.setattr(stdio_module.sys, "stdout", SimpleNamespace(buffer=io.BytesIO()))

    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "contract-1",
            "method": "tools/call",
            "params": {
                "name": "fetch",
                "arguments": {"url": "http://169.254.169.254/latest/meta-data"},
            },
        }
    ).encode()

    forwarded = asyncio.run(proxy._intercept_request(raw))
    assert forwarded is None
    assert len(test_state.events) == 1

    event = test_state.events[0]
    assert event["event_id"]
    assert event["hostname"]
    assert event["correlation_id"] == "contract-1"
    assert "control_id" in event
    assert "rule_name" in event
    assert isinstance(event["findings"], list)
    assert event["findings"]
    assert isinstance(event["findings"][0]["matched"], str)
