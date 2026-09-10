from fastapi import APIRouter, HTTPException
import httpx
from typing import Dict, Any, List

router = APIRouter(prefix="/api/investigations", tags=["Investigations Dashboard"])

GATEWAY_URL = "http://127.0.0.1:8000/api/v1/investigations"

@router.get("", summary="Get all active and past security investigations")
async def get_investigations():
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(GATEWAY_URL)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"Warning: Failed to fetch investigations from gateway: {e}")
        
    # Return default fallback list
    from backend.services.mock_data import MOCK_EVENTS
    from datetime import datetime
    
    items = []
    for ev in MOCK_EVENTS:
        ev_id = ev.get("event_id", "evt_001")
        items.append({
            "investigation_id": f"inv_{ev_id.replace('evt_', '')}",
            "event_id": ev_id,
            "title": f"Incident Investigation: {ev.get('risk_category', 'THREAT')}",
            "status": "COMPLETED",
            "severity": "CRITICAL" if ev.get("risk_score", 0) >= 0.8 else "HIGH",
            "risk_score": int(ev.get("risk_score", 0) * 100),
            "threat_category": ev.get("risk_category", "DATA_EXFILTRATION"),
            "agent_id": ev.get("agent_id", "devops-agent-01"),
            "started_at": ev.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "completed_at": ev.get("timestamp", datetime.utcnow().isoformat() + "Z")
        })
    return {"total": len(items), "items": items}

@router.get("/{investigation_id}", summary="Get detailed investigation workspace data")
async def get_investigation_detail(investigation_id: str):
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{GATEWAY_URL}/{investigation_id}")
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"Warning: Failed to fetch investigation detail from gateway: {e}")
        
    # Fallback default investigation
    return {
        "investigation_id": investigation_id,
        "event_id": investigation_id.replace("inv_", "evt_"),
        "title": "Data Exfiltration Attempt",
        "status": "COMPLETED",
        "severity": "CRITICAL",
        "risk_score": 94,
        "threat_category": "DATA_EXFILTRATION",
        "agent_id": "devops-agent-01",
        "started_at": "2026-08-30T07:30:02Z",
        "completed_at": "2026-08-30T07:30:07Z",
        "trigger": {
            "event_id": "evt_8f92a1",
            "agent_id": "devops-agent-01",
            "tool": "send_email",
            "resource": "customer_data.csv",
            "destination": "attacker@external.com",
            "decision": "BLOCK",
            "policy_id": "RULE-001"
        },
        "timeline": [
            {
                "step_id": "step_001",
                "phase": "Starting",
                "relative_time": "5s ago",
                "title": "Investigation Started",
                "description": "Zero-Trust Gateway intercepted anomaly on agent 'devops-agent-01'.",
                "timestamp": "2026-08-30T07:30:02Z",
                "data": {"incident_id": investigation_id, "trigger": "Critical Alert"}
            },
            {
                "step_id": "step_002",
                "phase": "Planning",
                "relative_time": "4s ago",
                "title": "Action Context Retrieved",
                "description": "Examined payload: tool 'send_email', resource 'customer_data.csv', destination 'attacker@external.com'.",
                "timestamp": "2026-08-30T07:30:03Z",
                "data": {"tool": "send_email", "resource": "customer_data.csv"}
            },
            {
                "step_id": "step_003",
                "phase": "Intent Analysis",
                "relative_time": "3s ago",
                "title": "Intent Analysis (Gemma-Edge)",
                "description": "Intent Engine evaluated contextual prompt tokens. Detected external data transfer.",
                "timestamp": "2026-08-30T07:30:04Z",
                "data": {"detected_intent": "External data transfer", "confidence": 0.98}
            },
            {
                "step_id": "step_004",
                "phase": "Risk Scoring",
                "relative_time": "2s ago",
                "title": "Risk Analysis",
                "description": "Multi-dimensional risk score computed: 94/100 (CRITICAL).",
                "timestamp": "2026-08-30T07:30:05Z",
                "data": {"risk_score": 94, "category": "DATA_EXFILTRATION"}
            },
            {
                "step_id": "step_005",
                "phase": "Policy Evaluation",
                "relative_time": "1s ago",
                "title": "Policy Evaluation",
                "description": "RULE-001 (Sensitive Data External Transfer) matched with fail-closed guarantee.",
                "timestamp": "2026-08-30T07:30:06Z",
                "data": {"policy_id": "RULE-001", "decision": "BLOCK"}
            },
            {
                "step_id": "step_006",
                "phase": "Decision",
                "relative_time": "Just now",
                "title": "Decision Enforced: BLOCKED",
                "description": "Gateway quarantined payload and persisted SHA-256 evidence to Immutable Audit Ledger.",
                "timestamp": "2026-08-30T07:30:07Z",
                "data": {"decision": "BLOCK", "remediation": "Memory sanitized."}
            }
        ],
        "root_cause": {
            "summary": "Agent attempted to transfer sensitive customer dataset to an unauthorized external email destination.",
            "confidence": 0.96,
            "causal_chain": [
                {"step": 1, "name": "Sensitive Data Access", "detail": "customer_data.csv accessed", "severity": "HIGH"},
                {"step": 2, "name": "External Destination Detected", "detail": "attacker@external.com", "severity": "CRITICAL"},
                {"step": 3, "name": "Policy RULE-001 Matched", "detail": "Outbound sensitive transfer prohibited", "severity": "CRITICAL"},
                {"step": 4, "name": "Action Blocked", "detail": "Execution halted in 3.2ms", "severity": "RESOLVED"}
            ],
            "factors": [
                {"name": "Sensitive Data Exposure", "severity": "CRITICAL"},
                {"name": "External Destination", "severity": "CRITICAL"}
            ]
        },
        "findings": [
            {"id": "f1", "title": "1. Sensitive Data Detected", "description": "customer_data.csv contains customer-identifiable information.", "severity": "CRITICAL"},
            {"id": "f2", "title": "2. External Destination", "description": "Destination is outside approved organizational domains.", "severity": "CRITICAL"},
            {"id": "f3", "title": "3. Policy Violation", "description": "RULE-001 prohibits external transfer of sensitive data.", "severity": "HIGH"},
            {"id": "f4", "title": "4. Agent Action Blocked", "description": "Zero-trust gateway prevented socket execution.", "severity": "RESOLVED"}
        ],
        "hypotheses": [
            {"id": "h1", "title": "1. Malicious Data Exfiltration", "confidence": 91, "status": "SUPPORTED"},
            {"id": "h2", "title": "2. Compromised Agent Context", "confidence": 67, "status": "PENDING"},
            {"id": "h3", "title": "3. Legitimate External Transfer", "confidence": 12, "status": "REJECTED"}
        ],
        "mitigation": {
            "status": "CONTAINED",
            "playbook_id": "PB-DATA-EXFIL",
            "automated_actions_completed": [
                {"action": "Block Action", "status": "SUCCESS", "detail": "Prevented tool invocation."},
                {"action": "Preserve Event Evidence", "status": "SUCCESS", "detail": "Signed SHA-256 evidence record."},
                {"action": "Flag Incident", "status": "SUCCESS", "detail": "Dispatched to telemetry dashboard."},
                {"action": "Record Audit Event", "status": "SUCCESS", "detail": "Persisted to audit ledger."}
            ],
            "recommended_human_actions": [
                {"action": "Review Agent Permissions", "priority": "HIGH", "detail": "Restrict send_email tool permission for devops-agent-01."},
                {"action": "Review Destination Policy", "priority": "HIGH", "detail": "Verify egress rules for external domains."},
                {"action": "Inspect Recent Agent Actions", "priority": "MEDIUM", "detail": "Audit preceding tool calls in session."},
                {"action": "Rotate Credentials If Compromise Suspected", "priority": "MEDIUM", "detail": "Invalidate active session tokens."}
            ]
        }
    }
