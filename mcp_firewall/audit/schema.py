"""Audit schema helpers for normalization and required metadata fields."""

from __future__ import annotations

from typing import Any

from ..models import PipelineDecision

REQUIRED_AUDIT_FIELDS = (
    "id",
    "timestamp",
    "agent_id",
    "tool_name",
    "arguments_hash",
    "decision",
    "stage",
    "reason",
    "severity",
    "latency_ms",
    "correlation_id",
    "control_id",
    "rule_name",
    "previous_hash",
)


def extract_decision_metadata(decision: PipelineDecision | None) -> dict[str, str]:
    """Extract control metadata from a pipeline decision."""
    if decision is None:
        return {"control_id": "", "rule_name": ""}

    details: dict[str, Any] = decision.details or {}
    control_id = str(details.get("control_id", ""))
    rule_name = str(details.get("rule_name", details.get("rule", "")))
    return {"control_id": control_id, "rule_name": rule_name}
