"""Exfil detector — blocks outbound exfiltration-like payloads."""

from __future__ import annotations

import re

from ..base import OutboundStage
from ...models import Action, GatewayConfig, PipelineDecision, PipelineStage, Severity, ToolCallResponse


BASE64_CHUNK = re.compile(r"[A-Za-z0-9+/=_-]{120,}")
DNS_TUNNEL = re.compile(r"\b(?:[a-z0-9-]{20,}\.){3,}[a-z]{2,}\b", re.IGNORECASE)


class ExfilDetector(OutboundStage):
    """Detect suspicious encoded or DNS-like exfiltration strings."""

    stage = PipelineStage.EXFIL_DETECTOR

    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        if not config.exfil.enabled:
            return response, None

        for content_item in response.content:
            text = content_item.get("text", "")
            if not text:
                continue
            if BASE64_CHUNK.search(text) or DNS_TUNNEL.search(text):
                decision = PipelineDecision(
                    stage=self.stage,
                    action=config.exfil.action,
                    reason="Exfiltration pattern detected in response content",
                    severity=Severity.HIGH,
                )
                return response, decision

        return response, None
