"""Tests for HTTP transport authentication and token audience validation."""

from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient

from mcp_firewall.models import GatewayConfig
from mcp_firewall.proxy.http import create_http_app


def _make_token(payload: dict[str, object]) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}."


def test_rejects_token_with_wrong_audience() -> None:
    config = GatewayConfig()
    config.auth.enabled = True
    config.auth.allowed_audiences = ["mcp-firewall"]

    client = TestClient(create_http_app(config))
    bad_aud_token = _make_token({"aud": "other-service"})

    response = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {bad_aud_token}"},
        json={"jsonrpc": "2.0"},
    )

    assert response.status_code == 401
    assert "invalid audience" in response.json()["detail"].lower()
