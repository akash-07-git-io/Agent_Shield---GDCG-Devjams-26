from fastapi import APIRouter, HTTPException
from backend.models.security_event import ApprovalRequest
from backend.services.gateway_client import resolve_escrow
from datetime import datetime, timezone

router = APIRouter(prefix="/api/approval", tags=["Approval"])

@router.post("/{event_id}", description="Approve or reject an event in ESCROW/REVIEW state")
async def process_approval(event_id: str, request: ApprovalRequest):
    dec = request.decision.upper()
    if dec not in ["APPROVE", "REJECT", "ALLOW", "BLOCK"]:
        raise HTTPException(status_code=400, detail="Invalid approval decision. Must be APPROVE or REJECT.")
    
    # Normalize decision to APPROVE or REJECT
    norm_dec = "APPROVE" if dec in ["APPROVE", "ALLOW"] else "REJECT"
    reviewer = request.reviewer or "security-admin"
    
    success = resolve_escrow(event_id, norm_dec, reviewer=reviewer, comment=request.comment)
    
    return {
        "event_id": event_id,
        "decision": norm_dec,
        "status": "RESOLVED",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
