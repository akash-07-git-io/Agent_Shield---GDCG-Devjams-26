from pydantic import BaseModel
from typing import Optional

class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    agent_id: str
    tool: str
    action: str
    resource: str
    destination: Optional[str] = None
    risk_score: float
    risk_category: str
    decision: str
    reason: str
    policy_id: Optional[str] = None

class ApprovalRequest(BaseModel):
    decision: str
