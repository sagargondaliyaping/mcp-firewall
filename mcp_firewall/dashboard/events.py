"""Normalized dashboard event helpers."""

from __future__ import annotations

import socket
import time
import uuid
from typing import Any

from ..models import DashboardEvent, DashboardFinding


def build_dashboard_event(
    *,
    action: str,
    tool: str,
    severity: str,
    reason: str = "",
    agent: str = "unknown",
    stage: str | None = None,
    timestamp: float | None = None,
    findings: list[dict[str, Any]] | None = None,
    correlation_id: str | None = None,
    server_id: str = "default",
    control_id: str = "",
    rule_name: str = "",
    target_hostname: str = "",
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    """Build a normalized dashboard event payload."""
    finding_models = [DashboardFinding.model_validate(item) for item in (findings or [])]
    event = DashboardEvent(
        server_id=server_id,
        hostname=socket.gethostname(),
        target_hostname=target_hostname,
        correlation_id=correlation_id or str(uuid.uuid4()),
        control_id=control_id,
        rule_name=rule_name,
        action=action,
        tool=tool,
        severity=severity,
        reason=reason,
        agent=agent,
        stage=stage,
        findings=finding_models,
        latency_ms=latency_ms,
        timestamp=timestamp if timestamp is not None else time.time(),
    )
    return event.model_dump()
