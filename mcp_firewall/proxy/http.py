"""HTTP MCP proxy entrypoint with bearer-token gate."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException

from ..models import GatewayConfig
from ..security.token_validation import TokenValidationError, validate_bearer_token


def create_http_app(config: GatewayConfig) -> FastAPI:
    """Create a minimal HTTP endpoint for MCP requests."""
    app = FastAPI(title="mcp-firewall HTTP Proxy", docs_url=None, redoc_url=None)

    @app.post("/mcp")
    async def mcp_endpoint(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if config.auth.enabled:
            try:
                validate_bearer_token(
                    authorization,
                    allowed_audiences=config.auth.allowed_audiences,
                    required_issuer=config.auth.required_issuer,
                )
            except TokenValidationError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc

        return {"jsonrpc": payload.get("jsonrpc", "2.0"), "result": {"ok": True}}

    return app
