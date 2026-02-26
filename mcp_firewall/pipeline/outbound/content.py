"""Content policy stage — applies custom pattern-based outbound blocking."""

from __future__ import annotations

import re

from ..base import OutboundStage
from ...models import GatewayConfig, PipelineDecision, PipelineStage, Severity, ToolCallResponse


class ContentPolicy(OutboundStage):
    """Apply custom block patterns to outbound text content."""

    stage = PipelineStage.CONTENT_POLICY

    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        if not config.content.enabled or not config.content.block_patterns:
            return response, None

        for content_item in response.content:
            text = content_item.get("text", "")
            if not text:
                continue
            for pattern in config.content.block_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    decision = PipelineDecision(
                        stage=self.stage,
                        action=config.content.action,
                        reason=f"Content policy violation: pattern '{pattern}' matched",
                        severity=Severity.MEDIUM,
                    )
                    return response, decision

        return response, None
