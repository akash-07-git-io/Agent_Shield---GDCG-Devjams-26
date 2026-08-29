from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from backend.services import gateway_client
from backend.services.mock_data import mock_events, mock_approvals
from datetime import datetime, timezone

router = APIRouter(prefix="/api/escrow", tags=["Escrow"])

class EscrowResolveRequest(BaseModel):
    action: str
    reviewer: str
    comment: str

@router.get("", description="Get all escrow events")
async def get_escrow(use_mock: bool = Query(False, description="Use mock data")):
    if use_mock:
        return [e for e in mock_events if e.decision in ["REVIEW", "ESCROW"]]
    return await gateway_client.get_escrow()

@router.get("/{escrow_id}", description="Get escrow details")
async def get_escrow_details(escrow_id: str, use_mock: bool = Query(False, description="Use mock data")):
    if use_mock:
        for e in mock_events:
            if e.event_id == escrow_id and e.decision in ["REVIEW", "ESCROW"]:
                return e
        raise HTTPException(status_code=404, detail="Escrow event not found")
    return await gateway_client.get_escrow_details(escrow_id)

@router.post("/{escrow_id}/resolve", description="Resolve an escrow event")
async def resolve_escrow(escrow_id: str, request: EscrowResolveRequest, use_mock: bool = Query(False, description="Use mock data")):
    if request.action not in ["APPROVE", "REJECT"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be APPROVE or REJECT.")
        
    if use_mock:
        mock_approvals[escrow_id] = {
            "decision": request.action,
            "reviewer": request.reviewer,
            "comment": request.comment,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        return {"escrow_id": escrow_id, "status": "RESOLVED_MOCK"}
        
    return await gateway_client.resolve_escrow(
        escrow_id=escrow_id,
        action=request.action,
        reviewer=request.reviewer,
        comment=request.comment
    )
