# Security Control Catalog

This catalog maps baseline security controls to concrete `mcp-firewall` components.

| Control ID | Standard | Requirement | mcp-firewall Component | Status |
|---|---|---|---|---|
| MCP-AUTH-001 | MCP + RFC9700 | Validate short-lived bearer tokens and audience | `proxy/http.py`, `security/token_validation.py` | implemented |
| MCP-INGRESS-001 | OWASP GenAI | Block prompt-injection and unsafe instruction override patterns | `pipeline/inbound/injection.py` | implemented |
| MCP-EGRESS-001 | OWASP GenAI | Block cloud metadata and private-network SSRF | `pipeline/inbound/egress.py` | implemented |
| MCP-POLICY-001 | NIST AI RMF | Enforce policy decisions before tool execution | `pipeline/inbound/policy.py` | implemented |
| MCP-THREAT-001 | NIST CSF 2.0 | Apply threat intelligence rules during runtime decisions | `pipeline/inbound/threat_feed.py` | implemented |
| MCP-ALERT-001 | NIST CSF 2.0 | Emit high-severity deny/redact events to responders | `alerts/engine.py` | implemented |
| MCP-AUDIT-001 | SSDF | Produce tamper-evident audit trails for tool actions | `audit/logger.py` | implemented |
| MCP-EXFIL-001 | OWASP GenAI | Detect and block outbound exfiltration patterns | `pipeline/outbound/exfil.py` | implemented |
| MCP-CONTENT-001 | NIST AI RMF | Enforce custom outbound content policy rules | `pipeline/outbound/content.py` | implemented |
