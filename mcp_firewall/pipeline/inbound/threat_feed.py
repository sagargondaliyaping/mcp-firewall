"""Threat feed stage — match requests against bundled/custom threat rules."""

from __future__ import annotations

from pathlib import Path

from ..base import InboundStage
from ...models import GatewayConfig, PipelineDecision, PipelineStage, ToolCallRequest
from ...threatfeed.loader import ThreatFeed


class ThreatFeedStage(InboundStage):
    """Evaluate inbound tool calls against loaded threat feed rules."""

    stage = PipelineStage.THREAT_FEED

    def __init__(self) -> None:
        self._feed = ThreatFeed()
        self._loaded = False

    def _ensure_loaded(self, config: GatewayConfig) -> None:
        if self._loaded:
            return

        builtins_dir = Path(__file__).resolve().parents[2] / "threatfeed" / "rules"
        self._feed.load_directory(builtins_dir)

        if config.threat_feed.rules_dir:
            self._feed.load_directory(config.threat_feed.rules_dir)

        self._loaded = True

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.threat_feed.enabled:
            return None

        self._ensure_loaded(config)
        rule = self._feed.check(request.tool_name, request.arguments)
        if rule is None:
            return None

        return self._deny(
            f"Threat feed match: {rule.id} {rule.name}",
            severity=rule.severity,
            details={"rule_id": rule.id, "rule_name": rule.name},
        )
