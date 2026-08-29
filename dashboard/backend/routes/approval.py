from fastapi import APIRouter, HTTPException
from backend.models.security_event import ApprovalRequest
from backend.services.gateway_client import resolve_escrow
from datetime import datetime, timezone

router = APIRouter(prefix="/api/approval", tags=["Approval"])

@router.post("/{event_id}", description="Approve or reject an event in ESCROW/REVIEW state")
async def process_approval(event_id: str, request: ApprovalRequest):
    if request.decision not in ["APPROVE", "REJECT"]:
        raise HTTPException(status_code=400, detail="Invalid approval decision. Must be APPROVE or REJECT.")
    
    success = resolve_escrow(event_id, request.decision)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to resolve escrow with security gateway")

    return {
        "event_id": event_id,
        "decision": request.decision,
        "status": "PROCESSED",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
