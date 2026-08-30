from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"

class ThreatCategory(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    GOAL_HIJACKING = "GOAL_HIJACKING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    TOOL_MISUSE = "TOOL_MISUSE"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    UNKNOWN_BEHAVIOR = "UNKNOWN_BEHAVIOR"

class SecurityDecision(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Decision timestamp")
    agent_id: str = Field(..., description="Agent ID")
    user_id: str = Field(..., description="User ID")
    tool: str = Field(..., description="Tool name")
    action: str = Field(..., description="Action verb")
    resource: str = Field(..., description="Target resource")
    destination: Optional[str] = Field(default=None, description="Target destination")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Evaluated risk score")
    risk_category: ThreatCategory = Field(default=ThreatCategory.NONE, description="Categorized threat")
    decision: DecisionType = Field(..., description="Enforced security decision")
    reason: str = Field(..., description="Clear explanation for decision")
    policy_id: Optional[str] = Field(default=None, description="Matched policy ID")
    model_version: str = Field(default="model-armor-v1.0+gemma-edge", description="Security model version")
    latency_ms: float = Field(default=0.0, description="Latency in ms")
    remediation: Optional[str] = Field(default=None, description="Remediation applied")
    escrow_id: Optional[str] = Field(default=None, description="Escrow ID if held")

class InterceptResponse(BaseModel):
    allowed: bool = Field(..., description="True if action is permitted")
    decision: DecisionType = Field(..., description="Decision enum")
    risk_score: float = Field(..., description="Evaluated risk score")
    threat_category: ThreatCategory = Field(..., description="Identified threat category")
    reason: str = Field(..., description="Decision explanation")
    event_id: str = Field(..., description="Audit event ID")
    latency_ms: float = Field(..., description="Processing time in ms")
    remediation: Optional[str] = Field(default=None, description="Remediation applied")
    escrow_id: Optional[str] = Field(default=None, description="Escrow identifier")
    action_result: Optional[Any] = Field(default=None, description="Tool execution output")
