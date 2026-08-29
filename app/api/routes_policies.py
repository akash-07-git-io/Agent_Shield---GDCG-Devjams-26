from typing import List
from fastapi import APIRouter, Depends
from app.api.routes_gateway import get_engine
from app.core.decision_engine import DecisionEngine
from app.models.policy import PolicyConfig, PolicyRule

router = APIRouter(prefix="/policies", tags=["Policies"])

@router.get("", response_model=List[PolicyRule], summary="List active security policies")
async def list_policies(engine: DecisionEngine = Depends(get_engine)) -> List[PolicyRule]:
    return engine.policy_engine.config.rules

@router.post("/reload", response_model=PolicyConfig, summary="Reload policies from YAML")
async def reload_policies(engine: DecisionEngine = Depends(get_engine)) -> PolicyConfig:
    config = engine.policy_engine.load_policies()
    engine.policy_engine.config = config
    return config
