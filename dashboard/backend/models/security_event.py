from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class IntentAnalysis(BaseModel):
    intent: Optional[str] = None
    risk_indicators: List[str] = Field(default_factory=list)
    confidence: float = 0.0

class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    agent_id: str
    user_id: Optional[str] = "developer-01"
    tool: str
    action: str
    resource: str
    destination: Optional[str] = None
    context: Optional[str] = None
    risk_score: float
    risk_category: str
    decision: str
    reason: str
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    intent_analysis: Optional[IntentAnalysis] = None
    model_version: Optional[str] = "model-armor-v1.0+gemma-edge"
    latency_ms: Optional[float] = 18.4
    remediation: Optional[str] = None
    playbook: Optional[str] = None
    payload_preview: Optional[str] = None
    escrow_id: Optional[str] = None
    hash_signature: Optional[str] = None

class ApprovalRequest(BaseModel):
    decision: str
    reviewer: Optional[str] = "security-admin"
    comment: Optional[str] = None

class SimulateRequest(BaseModel):
    scenario_id: str
