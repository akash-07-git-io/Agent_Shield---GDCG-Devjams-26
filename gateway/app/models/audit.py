from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.models.action import NormalizedAction
from app.models.decision import DecisionType, ThreatCategory

class EscrowStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class AuditEvent(BaseModel):
    event_id: str = Field(..., description="Unique event ID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of event")
    agent_id: str = Field(..., description="Agent ID")
    user_id: str = Field(..., description="User ID")
    tool: str = Field(..., description="Tool name")
    action: str = Field(..., description="Action verb")
    resource: str = Field(..., description="Target resource")
    destination: Optional[str] = Field(default=None, description="Target destination")
    context: Optional[str] = Field(default=None, description="Context of operation")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Evaluated risk score")
    risk_category: ThreatCategory = Field(..., description="Threat category")
    decision: DecisionType = Field(..., description="Security decision")
    reason: str = Field(..., description="Clear explanation for decision")
    policy_id: Optional[str] = Field(default=None, description="Matched policy ID")
    model_version: str = Field(default="model-armor-v1.0+gemma-edge", description="Security model version")
    latency_ms: float = Field(default=0.0, description="Latency in ms")
    remediation: Optional[str] = Field(default=None, description="Remediation applied")
    escrow_id: Optional[str] = Field(default=None, description="Escrow ID if held in escrow")
    payload_preview: Optional[str] = Field(default=None, description="Truncated preview of payload")

class AuditSummary(BaseModel):
    total_events: int = 0
    actions_allowed: int = 0
    actions_warned: int = 0
    actions_in_escrow: int = 0
    actions_blocked: int = 0
    actions_isolated: int = 0
    threats_detected: int = 0
    average_risk_score: float = 0.0
    average_latency_ms: float = 0.0
    security_posture_score: int = 100
    threat_breakdown: Dict[str, int] = Field(default_factory=dict)
    recent_events: List[AuditEvent] = Field(default_factory=list)

class EscrowItem(BaseModel):
    escrow_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    status: EscrowStatus = EscrowStatus.PENDING
    action: NormalizedAction
    risk_score: float
    threat_category: ThreatCategory
    reason: str
    policy_id: Optional[str] = None
    reviewer: Optional[str] = None
    review_comment: Optional[str] = None

class EscrowResolveRequest(BaseModel):
    action: str = Field(..., description="'APPROVE' or 'REJECT'")
    reviewer: str = Field(default="security-admin", description="Reviewer identity")
    comment: Optional[str] = Field(default=None, description="Review rationale")
