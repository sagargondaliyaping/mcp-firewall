"""Core data models for mcp-firewall."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Action(str, Enum):
    """Policy decision actions."""

    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    PROMPT = "prompt"  # ask human
    ALERT = "alert"  # allow but alert


class Severity(str, Enum):
    """Alert/finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank


class PipelineStage(str, Enum):
    """Pipeline stage identifiers."""

    KILL_SWITCH = "kill_switch"
    AGENT_IDENTITY = "agent_identity"
    RATE_LIMITER = "rate_limiter"
    INJECTION = "injection"
    EGRESS = "egress"
    THREAT_FEED = "threat_feed"
    POLICY = "policy"
    CHAIN_DETECTOR = "chain_detector"
    HUMAN_APPROVAL = "human_approval"
    SECRET_SCANNER = "secret_scanner"
    PII_DETECTOR = "pii_detector"
    EXFIL_DETECTOR = "exfil_detector"
    CONTENT_POLICY = "content_policy"


class ToolCallRequest(BaseModel):
    """Represents an incoming MCP tool call request."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = "unknown"
    timestamp: float = Field(default_factory=time.time)


class ToolCallResponse(BaseModel):
    """Represents an MCP tool call response."""

    request_id: str
    content: list[dict[str, Any]] = Field(default_factory=list)
    is_error: bool = False
    timestamp: float = Field(default_factory=time.time)


class PipelineDecision(BaseModel):
    """Result of a pipeline stage evaluation."""

    stage: PipelineStage
    action: Action
    reason: str = ""
    severity: Severity = Severity.INFO
    details: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    """Immutable audit log entry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    agent_id: str = "unknown"
    tool_name: str = ""
    arguments_hash: str = ""  # SHA-256 of arguments (not raw for privacy)
    decision: Action = Action.ALLOW
    stage: PipelineStage | None = None
    reason: str = ""
    severity: Severity = Severity.INFO
    latency_ms: float = 0.0
    correlation_id: str = ""
    control_id: str = ""
    rule_name: str = ""
    previous_hash: str = ""  # hash chain


class DashboardFinding(BaseModel):
    """Structured finding attached to a dashboard event."""

    type: str
    matched: str = ""
    confidence: float = 1.0
    action: str = ""


class DashboardEvent(BaseModel):
    """Normalized dashboard event payload."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str
    target_hostname: str = ""
    correlation_id: str
    control_id: str = ""
    rule_name: str = ""
    action: str
    tool: str
    severity: str = "info"
    reason: str = ""
    agent: str = "unknown"
    stage: str | None = None
    findings: list[DashboardFinding] = Field(default_factory=list)
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class GatewayConfig(BaseModel):
    """Top-level gateway configuration."""

    version: int = 1
    default_action: Action = Action.PROMPT
    kill_switch: KillSwitchConfig = Field(default_factory=lambda: KillSwitchConfig())
    rate_limit: RateLimitConfig = Field(default_factory=lambda: RateLimitConfig())
    injection: InjectionConfig = Field(default_factory=lambda: InjectionConfig())
    egress: EgressConfig = Field(default_factory=lambda: EgressConfig())
    auth: AuthConfig = Field(default_factory=lambda: AuthConfig())
    threat_feed: ThreatFeedConfig = Field(default_factory=lambda: ThreatFeedConfig())
    secrets: SecretScanConfig = Field(default_factory=lambda: SecretScanConfig())
    pii: PIIConfig = Field(default_factory=lambda: PIIConfig())
    exfil: ExfilConfig = Field(default_factory=lambda: ExfilConfig())
    content: ContentPolicyConfig = Field(default_factory=lambda: ContentPolicyConfig())
    alerts: AlertsConfig = Field(default_factory=lambda: AlertsConfig())
    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    rules: list[RuleConfig] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=lambda: AuditConfig())


class KillSwitchConfig(BaseModel):
    """Kill switch configuration."""

    enabled: bool = True
    file_path: str = ".mcp-firewall-kill"


class RateLimitConfig(BaseModel):
    """Global rate limit configuration."""

    enabled: bool = True
    max_calls: int = 200
    window_seconds: int = 60


class InjectionConfig(BaseModel):
    """Injection detection configuration."""

    enabled: bool = True
    sensitivity: str = "medium"  # low, medium, high


class EgressConfig(BaseModel):
    """Egress control configuration."""

    enabled: bool = True
    block_private_ips: bool = True
    block_cloud_metadata: bool = True


class AuthConfig(BaseModel):
    """HTTP transport authentication configuration."""

    enabled: bool = True
    allowed_audiences: list[str] = Field(default_factory=lambda: ["mcp-firewall"])
    required_issuer: str | None = None


class ThreatFeedConfig(BaseModel):
    """Threat feed configuration."""

    enabled: bool = True
    rules_dir: str | None = None


class SecretScanConfig(BaseModel):
    """Secret scanning configuration."""

    enabled: bool = True
    action: Action = Action.REDACT


class PIIConfig(BaseModel):
    """PII detection configuration."""

    enabled: bool = False  # off by default
    action: Action = Action.REDACT


class ExfilConfig(BaseModel):
    """Outbound exfiltration detection configuration."""

    enabled: bool = True
    action: Action = Action.DENY


class ContentPolicyConfig(BaseModel):
    """Custom content policy configuration."""

    enabled: bool = False
    block_patterns: list[str] = Field(default_factory=list)
    action: Action = Action.DENY


class AlertsConfig(BaseModel):
    """Alerting configuration."""

    enabled: bool = False
    min_severity: Severity = Severity.HIGH


class AgentConfig(BaseModel):
    """Per-agent RBAC configuration."""

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    rate_limit: str | None = None  # e.g. "100/min"
    require_approval: list[str] = Field(default_factory=list)


class RuleConfig(BaseModel):
    """Individual policy rule."""

    name: str
    tool: str = "*"
    match: dict[str, Any] = Field(default_factory=dict)
    action: Action = Action.DENY
    message: str = ""
    rate_limit: dict[str, int] | None = None


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    enabled: bool = True
    path: str = "mcp-firewall.audit.jsonl"
    sign: bool = False  # Ed25519 signing (Phase 4)
    max_size_mb: int = 100
