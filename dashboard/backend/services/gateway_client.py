import httpx
from typing import List, Dict, Any
from backend.services.mock_data import mock_events

GATEWAY_URL = "http://localhost:8000/api/v1"

def get_live_events() -> List[Dict[str, Any]]:
    try:
        response = httpx.get(f"{GATEWAY_URL}/audit/events", timeout=2.0)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching live events: {e}")
        # Fallback to mock data format mapped to new schema
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "tool": e.tool,
                "action": e.action,
                "resource": e.resource,
                "destination": e.destination,
                "risk_score": float(e.risk_score),
                "risk_category": getattr(e, "category", "UNKNOWN"),
                "decision": e.decision,
                "reason": e.reason,
                "policy_id": e.policy_id
            } for e in mock_events
        ]

def get_live_stats() -> Dict[str, Any]:
    try:
        response = httpx.get(f"{GATEWAY_URL}/audit/summary", timeout=2.0)
        response.raise_for_status()
        data = response.json()
        return {
            "total_actions": data.get("total_events", 0),
            "allowed": data.get("actions_allowed", 0),
            "blocked": data.get("actions_blocked", 0),
            "review": data.get("actions_in_escrow", 0),
            "threats_detected": data.get("threats_detected", 0),
            "security_score": data.get("security_posture_score", 100)
        }
    except Exception as e:
        print(f"Error fetching live stats: {e}")
        total_actions = len(mock_events)
        allowed = sum(1 for e in mock_events if e.decision == "ALLOW")
        blocked = sum(1 for e in mock_events if e.decision == "BLOCK")
        review = sum(1 for e in mock_events if e.decision == "REVIEW" or e.decision == "ESCROW")
        return {
            "total_actions": total_actions,
            "allowed": allowed,
            "blocked": blocked,
            "review": review,
            "threats_detected": blocked + review,
            "security_score": max(0, 100 - (blocked * 10) - (review * 5))
        }

def resolve_escrow(event_id: str, decision: str) -> bool:
    try:
        response = httpx.post(
            f"{GATEWAY_URL}/escrow/{event_id}/resolve",
            json={"action": decision, "reviewer": "dashboard-admin", "comment": "Approved via UI"},
            timeout=2.0
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error resolving escrow: {e}")
        return False
