from fastapi import APIRouter, Query
from backend.services.mock_data import mock_events
from backend.services import gateway_client

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", description="Get overall dashboard statistics")
async def get_dashboard_stats(use_mock: bool = Query(False, description="Use mock data")):
    if use_mock:
        total_actions = len(mock_events)
        allowed = sum(1 for e in mock_events if e.decision == "ALLOW")
        blocked = sum(1 for e in mock_events if e.decision == "BLOCK")
        review = sum(1 for e in mock_events if e.decision == "REVIEW" or e.decision == "ESCROW")
        threats_detected = blocked + review
        
        base_score = 100
        penalty = (blocked * 10) + (review * 5)
        security_score = max(0, base_score - penalty)

        return {
            "total_actions": total_actions,
            "allowed": allowed,
            "blocked": blocked,
            "review": review,
            "threats_detected": threats_detected,
            "security_score": security_score
        }
        
    summary = await gateway_client.get_audit_summary()
    
    stats = {
        "total_actions": summary.get("total_actions", 0),
        "allowed": summary.get("allowed", summary.get("actions_allowed", 0)),
        "blocked": summary.get("blocked", summary.get("actions_blocked", 0)),
        "review": summary.get("review", summary.get("actions_in_escrow", 0)),
        "threats_detected": summary.get("threats_detected", 0),
        "security_score": summary.get("security_score", summary.get("security_posture_score", 100))
    }
    
    for k, v in summary.items():
        if k not in stats:
            stats[k] = v
            
    return stats
