from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class RawToolCall(BaseModel):
    tool_name: str = Field(..., description="Name of the tool being invoked")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments passed to the tool")
    agent_id: str = Field(default="devops-agent-01", description="Identifier of calling agent")
    user_id: str = Field(default="developer-01", description="Identifier of user")
    context: Optional[str] = Field(default="Autonomous DevOps Task", description="Current context")
    raw_prompt: Optional[str] = Field(default=None, description="Original user prompt")

class NormalizedAction(BaseModel):
    agent_id: str = Field(..., description="Agent ID")
    user_id: str = Field(..., description="User ID")
    tool: str = Field(..., description="Tool name")
    action: str = Field(..., description="Action verb")
    resource: str = Field(..., description="Target resource")
    destination: Optional[str] = Field(default=None, description="Destination target")
    context: str = Field(default="General DevOps Operation", description="Operational context")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Normalized payload")
    raw_prompt: Optional[str] = Field(default=None, description="Raw prompt")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp")

class InterceptRequest(BaseModel):
    raw_call: Optional[RawToolCall] = None
    action: Optional[NormalizedAction] = None
    simulate: bool = Field(default=False, description="If true, evaluates without side-effects")
