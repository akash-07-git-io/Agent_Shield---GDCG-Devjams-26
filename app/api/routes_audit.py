from typing import List
from fastapi import APIRouter, Depends, Query
from app.api.routes_gateway import get_engine
from app.core.decision_engine import DecisionEngine
from app.models.audit import AuditEvent, AuditSummary

router = APIRouter(prefix="/audit", tags=["Audit Ledger & Telemetry"])

@router.get("/events", response_model=List[AuditEvent], summary="Query immutable audit log events")
async def get_audit_events(
    limit: int = Query(50, ge=1, le=500, description="Max number of records"),
    offset: int = Query(0, ge=0, description="Offset"),
    engine: DecisionEngine = Depends(get_engine)
) -> List[AuditEvent]:
    return engine.audit_ledger.get_events(limit=limit, offset=offset)

@router.get("/summary", response_model=AuditSummary, summary="Get aggregate security posture & metrics")
async def get_audit_summary(
    engine: DecisionEngine = Depends(get_engine)
) -> AuditSummary:
    return engine.audit_ledger.get_summary()

@router.get("/health", summary="Health check and engine metrics")
async def get_health_status(engine: DecisionEngine = Depends(get_engine)):
    return {
        "status": "healthy",
        "gateway": "online",
        "model_armor": engine.model_armor.model_version,
        "fail_closed": True,
        "active_policies_count": len(engine.policy_engine.config.rules),
        "total_events_logged": len(engine.audit_ledger.events)
    }
