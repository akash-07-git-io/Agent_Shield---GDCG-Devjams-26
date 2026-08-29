from fastapi import APIRouter, HTTPException
from backend.models.security_event import ApprovalRequest
from backend.services.mock_data import mock_events, mock_approvals
from datetime import datetime, timezone

router = APIRouter(prefix="/api/approval", tags=["Approval"])

@router.post("/{event_id}", description="Approve or reject an event in ESCROW/REVIEW state")
async def process_approval(event_id: str, request: ApprovalRequest):
    if request.decision not in ["APPROVE", "REJECT"]:
        raise HTTPException(status_code=400, detail="Invalid approval decision. Must be APPROVE or REJECT.")
    
    # Check if event exists
    event_exists = any(e.event_id == event_id for e in mock_events)
    if not event_exists:
        raise HTTPException(status_code=404, detail="Event not found")

    # Store the approval
    timestamp = datetime.now(timezone.utc).isoformat()
    mock_approvals[event_id] = {
        "decision": request.decision,
        "timestamp": timestamp
    }

    return {
        "event_id": event_id,
        "decision": request.decision,
        "status": "PROCESSED",
        "timestamp": timestamp
    }
