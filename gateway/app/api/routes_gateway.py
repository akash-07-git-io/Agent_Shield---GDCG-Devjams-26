from typing import Any, Dict, Union
from fastapi import APIRouter, Depends, HTTPException, Request
from app.core.decision_engine import DecisionEngine
from app.models.action import InterceptRequest, NormalizedAction, RawToolCall
from app.models.decision import InterceptResponse, SecurityDecision

router = APIRouter(prefix="/gateway", tags=["Gateway Interception"])

_engine = DecisionEngine()

def get_engine() -> DecisionEngine:
    return _engine

@router.post("/intercept", response_model=InterceptResponse, summary="Intercept & evaluate an AI agent tool call")
async def intercept_tool_call(
    request: Union[InterceptRequest, RawToolCall, NormalizedAction, Dict[str, Any]],
    engine: DecisionEngine = Depends(get_engine)
) -> InterceptResponse:
    if isinstance(request, InterceptRequest):
        input_data = request.action or request.raw_call
        simulate = request.simulate
    else:
        input_data = request
        simulate = False

    _, response = engine.process(input_data, simulate=simulate)
    return response

@router.post("/evaluate", response_model=SecurityDecision, summary="Simulate risk & policy evaluation without execution")
async def evaluate_action(
    request: Union[InterceptRequest, RawToolCall, NormalizedAction, Dict[str, Any]],
    engine: DecisionEngine = Depends(get_engine)
) -> SecurityDecision:
    if isinstance(request, InterceptRequest):
        input_data = request.action or request.raw_call
    else:
        input_data = request

    decision, _ = engine.process(input_data, simulate=True)
    return decision

@router.post("/actions/evaluate", response_model=SecurityDecision, summary="Standard Agent Action Evaluation")
async def standard_action_evaluate(
    request: Dict[str, Any],
    engine: DecisionEngine = Depends(get_engine)
) -> SecurityDecision:
    decision, _ = engine.process(request, simulate=False)
    return decision

@router.post("/agent/action", response_model=SecurityDecision, summary="Compatibility for agent actions")
async def compat_intercept_tool_call(
    request: Union[InterceptRequest, RawToolCall, NormalizedAction, Dict[str, Any]],
    engine: DecisionEngine = Depends(get_engine)
) -> SecurityDecision:
    decision, _ = engine.process(request, simulate=False)
    return decision
