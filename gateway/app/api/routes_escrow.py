from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from app.api.routes_gateway import get_engine
from app.core.decision_engine import DecisionEngine
from app.models.audit import EscrowItem, EscrowResolveRequest, EscrowStatus

router = APIRouter(prefix="/escrow", tags=["Escrow & Human Approval"])

@router.get("", response_model=List[EscrowItem], summary="List actions held in escrow")
async def list_escrow_items(
    status: Optional[EscrowStatus] = Query(None, description="Filter by status: PENDING, APPROVED, REJECTED"),
    engine: DecisionEngine = Depends(get_engine)
) -> List[EscrowItem]:
    return engine.audit_ledger.list_escrow(status=status)

@router.get("/{escrow_id}", response_model=EscrowItem, summary="Get specific escrow item")
async def get_escrow_item(
    escrow_id: str,
    engine: DecisionEngine = Depends(get_engine)
) -> EscrowItem:
    item = engine.audit_ledger.get_escrow_item(escrow_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Escrow item '{escrow_id}' not found")
    return item

@router.post("/{escrow_id}/resolve", response_model=EscrowItem, summary="Approve or reject escrowed action")
async def resolve_escrow_item(
    escrow_id: str,
    body: EscrowResolveRequest,
    engine: DecisionEngine = Depends(get_engine)
) -> EscrowItem:
    resolved = engine.audit_ledger.resolve_escrow(
        escrow_id=escrow_id,
        action=body.action,
        reviewer=body.reviewer,
        comment=body.comment
    )
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Escrow item '{escrow_id}' not found")
    return resolved
