from pydantic import BaseModel, Field
from typing import List, Optional

class ActionObject(BaseModel):
    """
    The Golden Interface: Normalized Action Object.
    Produced by Member 1, Evaluated by Member 2, Visualized by Member 3.
    """
    agent_id: str = Field(description="ID of the agent making the tool call")
    tool: str = Field(description="The name of the tool being called")
    action: str = Field(description="The specific action being performed (e.g., read, write, send)")
    resource: str = Field(description="The primary resource being accessed (e.g., file name, repo name)")
    destination: Optional[str] = Field(default=None, description="Where data is being sent, if applicable")
    context: str = Field(description="The high-level user context or goal behind this action")

class IntentObject(BaseModel):
    """
    Output of the Intent Engine.
    Provides structured context about the agent's action for the Security Gateway.
    """
    intent: str = Field(description="WHAT is the agent trying to do and WHY?")
    risk_indicators: List[str] = Field(description="List of detected risk factors (e.g., 'sensitive_data', 'instruction_override')")
    confidence: float = Field(description="Confidence score (0.0 to 1.0) of the intent analysis")
