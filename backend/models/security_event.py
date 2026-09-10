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
    risk_score: int
    severity: str
    category: str
    decision: str
    reason: str
    policy_id: str

class ApprovalRequest(BaseModel):
    decision: str
