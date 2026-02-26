"""Milestone B tests: HTTP auth and outbound exfil/content controls."""

from __future__ import annotations

from mcp_firewall.models import Action, GatewayConfig, PipelineStage, ToolCallRequest, ToolCallResponse
from mcp_firewall.pipeline.runner import PipelineRunner


def test_outbound_blocks_dns_tunnel_pattern() -> None:
    config = GatewayConfig(default_action=Action.ALLOW)
    config.audit.enabled = False
    config.exfil.enabled = True

    runner = PipelineRunner(config)
    request = ToolCallRequest(tool_name="search")
    response = ToolCallResponse(
        request_id="1",
        content=[{
            "type": "text",
            "text": "dGhpcy1pcy1hLXZlcnktbG9uZy1iYXNlNjQtZW5jb2RlZC1wYXlsb2FkLXRoYXQtbG9va3MtbGlrZS1leGZpbHRyYXRpb24="
                    "dGhpcy1pcy1hLXZlcnktbG9uZy1iYXNlNjQtZW5jb2RlZC1wYXlsb2FkLXRoYXQtbG9va3MtbGlrZS1leGZpbHRyYXRpb24=",
        }],
    )

    _, decisions = runner.scan_outbound(request, response)
    assert any(
        d.stage == PipelineStage.EXFIL_DETECTOR and d.action == Action.DENY
        for d in decisions
    )


def test_content_policy_blocks_forbidden_pattern() -> None:
    config = GatewayConfig(default_action=Action.ALLOW)
    config.audit.enabled = False
    config.content.enabled = True
    config.content.block_patterns = [r"internal-only"]

    runner = PipelineRunner(config)
    request = ToolCallRequest(tool_name="read_file")
    response = ToolCallResponse(
        request_id="2",
        content=[{"type": "text", "text": "this is internal-only material"}],
    )

    _, decisions = runner.scan_outbound(request, response)
    assert any(
        d.stage == PipelineStage.CONTENT_POLICY and d.action == Action.DENY
        for d in decisions
    )


def test_pipeline_decision_findings_include_secret_match() -> None:
    config = GatewayConfig(default_action=Action.ALLOW)
    config.audit.enabled = False
    config.secrets.enabled = True
    config.secrets.action = Action.REDACT

    runner = PipelineRunner(config)
    request = ToolCallRequest(tool_name="read_file")
    response = ToolCallResponse(
        request_id="3",
        content=[{"type": "text", "text": "token=AKIA1234567890ABCDEF"}],
    )

    _, decisions = runner.scan_outbound(request, response)
    assert decisions
    findings = runner.decision_findings(decisions[0])
    assert findings
    assert findings[0]["matched"]
