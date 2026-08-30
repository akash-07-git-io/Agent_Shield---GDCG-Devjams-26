from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.models.decision import DecisionType, ThreatCategory

class PolicyRule(BaseModel):
    id: str = Field(..., description="Unique rule ID, e.g. RULE-001")
    name: str = Field(..., description="Human readable rule name")
    description: str = Field(..., description="Rule description")
    enabled: bool = Field(default=True, description="Whether rule is active")
    priority: int = Field(default=100, description="Priority ordering")
    
    tools: Optional[List[str]] = Field(default=None, description="Matching tools")
    actions: Optional[List[str]] = Field(default=None, description="Matching actions")
    resource_patterns: Optional[List[str]] = Field(default=None, description="Patterns for resource")
    destination_patterns: Optional[List[str]] = Field(default=None, description="Patterns for destination")
    require_external_destination: Optional[bool] = Field(default=None, description="Destination is non-internal")
    min_risk_score: Optional[float] = Field(default=None, description="Triggers if calculated risk >= min_risk_score")
    require_prompt_injection: Optional[bool] = Field(default=None, description="Triggers if prompt injection detected")
    context_patterns: Optional[List[str]] = Field(default=None, description="Matching context patterns")
    
    decision: DecisionType = Field(..., description="Decision when policy matches")
    threat_category: ThreatCategory = Field(default=ThreatCategory.NONE, description="Category of threat")
    reason: str = Field(..., description="Reason template")
    remediation: Optional[str] = Field(default=None, description="Remediation action")

class PolicyConfig(BaseModel):
    version: str = Field(default="1.0.0", description="Policy version")
    fail_closed: bool = Field(default=True, description="Fail closed on error")
    default_decision: DecisionType = Field(default=DecisionType.ALLOW, description="Default decision")
    rules: List[PolicyRule] = Field(default_factory=list, description="Policy rules list")
