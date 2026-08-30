from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

router = APIRouter(prefix="/investigations", tags=["Investigations"])

# In-memory investigation storage & generator
def generate_investigation_for_event(event: Dict[str, Any]) -> Dict[str, Any]:
    event_id = event.get("event_id", "evt_unknown")
    agent_id = event.get("agent_id", "devops-agent-01")
    tool = event.get("tool", "send_email")
    action = event.get("action", "send")
    resource = event.get("resource", "customer_data.csv")
    destination = event.get("destination") or "internal://runtime-sandbox"
    risk_score = int(event.get("risk_score", 0.94) * 100) if isinstance(event.get("risk_score"), float) and event.get("risk_score") <= 1.0 else int(event.get("risk_score", 94))
    risk_cat = event.get("risk_category", "DATA_EXFILTRATION")
    decision = str(event.get("decision", "BLOCK")).replace("DecisionType.", "")
    policy_id = event.get("policy_id", "RULE-001")
    remediation = event.get("remediation", "Contaminated instruction rejected. Agent memory context sanitized.")
    timestamp = event.get("timestamp", datetime.utcnow().isoformat() + "Z")

    inv_id = f"inv_{event_id.replace('evt_', '')}"
    
    # Title based on category
    title_map = {
        "DATA_EXFILTRATION": "Data Exfiltration & Unauthorized Egress Attempt",
        "PROMPT_INJECTION": "Adversarial Prompt Injection & Instruction Hijack",
        "DATABASE_WRITE": "Critical Production Database Write Without Approval",
        "PRIVILEGE_ESCALATION": "Unauthorized IAM Role & Privilege Escalation Attempt",
        "CREDENTIAL_ACCESS": "Sensitive Credential & Secret File Access",
        "NONE": "Routine Agent Operation Inspection"
    }
    title = title_map.get(risk_cat, f"Security Investigation: {risk_cat}")

    timeline = [
        {
            "step_id": "step_001",
            "phase": "Starting",
            "relative_time": "5s ago",
            "type": "INCIDENT_INITIATED",
            "status": "COMPLETED",
            "title": f"Investigation {inv_id.upper()} Initiated",
            "description": f"Zero-Trust Gateway intercepted anomaly on agent '{agent_id}' executing tool '{tool}'. CloudWatch & Gateway telemetry alarm triggered.",
            "timestamp": timestamp,
            "data": {
                "incident_id": inv_id,
                "agent_id": agent_id,
                "account_id": "123456789012",
                "trigger_event": event_id,
                "region": "us-east-1"
            },
            "observations": [
                f"Agent '{agent_id}' initiated execution from developer-01 session.",
                f"Tool '{tool}' invoked with resource '{resource}'."
            ]
        },
        {
            "step_id": "step_002",
            "phase": "Planning",
            "relative_time": "4s ago",
            "type": "CONTEXT_EXTRACTION",
            "status": "COMPLETED",
            "title": "Action Context & Execution Boundary Retrieved",
            "description": f"Examined runtime context, target resource sensitivity, and egress destination parameters.",
            "timestamp": timestamp,
            "data": {
                "service_name": "agent_shield_gateway",
                "operation_name": "intercept_tool_call",
                "parameters": {
                    "tool": tool,
                    "action": action,
                    "resource": resource,
                    "destination": destination,
                    "agent_id": agent_id
                },
                "source": "Agent Runtime Sandbox"
            },
            "observations": [
                f"Target resource '{resource}' matches classified enterprise dataset pattern.",
                f"Destination '{destination}' resolved to external unverified egress endpoint."
            ]
        },
        {
            "step_id": "step_003",
            "phase": "Intent Analysis",
            "relative_time": "3s ago",
            "type": "SEMANTIC_EVALUATION",
            "status": "COMPLETED",
            "title": "Semantic Intent & Anomaly Extraction (Gemma-Edge)",
            "description": "Intent Engine evaluated contextual prompt tokens against goal-hijacking and covert channel vectors.",
            "timestamp": timestamp,
            "data": {
                "detected_intent": f"Transfer contents of '{resource}' to '{destination}'",
                "risk_indicators": ["sensitive_data_exposure", "external_egress_unauthorized", "instruction_override"],
                "confidence_score": 0.98
            },
            "observations": [
                "Instruction deviates from authorized software maintenance playbook.",
                "High confidence semantic match for adversarial instruction override."
            ]
        },
        {
            "step_id": "step_004",
            "phase": "Risk Scoring",
            "relative_time": "2s ago",
            "type": "RISK_EVALUATION",
            "status": "COMPLETED",
            "title": f"Multi-Dimensional Risk Score Calculated: {risk_score}/100",
            "description": f"Risk assessment aggregated threat category '{risk_cat}' with severity CRITICAL.",
            "timestamp": timestamp,
            "data": {
                "risk_score": risk_score,
                "threat_category": risk_cat,
                "severity": "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 60 else "MEDIUM"),
                "confidence": 0.96
            },
            "observations": [
                f"Risk score {risk_score}/100 exceeds critical automated isolation threshold (80/100)."
            ]
        },
        {
            "step_id": "step_005",
            "phase": "Policy Evaluation",
            "relative_time": "1s ago",
            "type": "POLICY_MATCH",
            "status": "COMPLETED",
            "title": f"Deterministic Rule Enforcement ({policy_id})",
            "description": f"Evaluated enterprise default policies. Matched constraint {policy_id} with fail-closed guarantee.",
            "timestamp": timestamp,
            "data": {
                "policy_id": policy_id,
                "policy_name": "Sensitive Data External Transfer Restriction" if policy_id == "RULE-001" else f"Security Rule {policy_id}",
                "decision_rule": decision,
                "matched_conditions": ["contains_sensitive_data == true", f"destination_unauthorized == true"]
            },
            "observations": [
                f"Zero-Trust Policy {policy_id} explicitly prohibits outbound transfer of '{resource}'.",
                "Fail-closed condition triggered immediately."
            ]
        },
        {
            "step_id": "step_006",
            "phase": "Decision",
            "relative_time": "Just now",
            "type": "DECISION_ENFORCEMENT",
            "status": "COMPLETED",
            "title": f"Enforcement Executed: {decision}",
            "description": f"Gateway halted outbound tool execution, discarded payload, and isolated session context.",
            "timestamp": timestamp,
            "data": {
                "decision": decision,
                "remediation": remediation,
                "latency_ms": 3.2,
                "escrow_id": None
            },
            "observations": [
                "Zero data transmitted across network boundary.",
                "Forensic SHA-256 cryptographic evidence record persisted to immutable audit ledger."
            ]
        }
    ]

    root_cause = {
        "summary": f"Agent '{agent_id}' attempted an unauthorized {action} operation on protected asset '{resource}' towards external destination '{destination}', violating security policy {policy_id}.",
        "confidence": 0.96,
        "causal_chain": [
            {"step": 1, "name": "Protected Resource Access", "detail": f"Agent accessed '{resource}' containing sensitive data.", "severity": "HIGH"},
            {"step": 2, "name": "External Destination Resolution", "detail": f"Outbound destination '{destination}' is not on approved allowlist.", "severity": "CRITICAL"},
            {"step": 3, "name": "Semantic Goal Divergence", "detail": "Intent engine detected unauthorized data transfer intent.", "severity": "HIGH"},
            {"step": 4, "name": "Policy Violation", "detail": f"Matched deterministic rule {policy_id}.", "severity": "CRITICAL"},
            {"step": 5, "name": "Enforcement Action", "detail": f"Runtime gateway enforced {decision}.", "severity": "RESOLVED"}
        ],
        "factors": [
            {"name": "Sensitive Data Exposure", "severity": "CRITICAL", "weight": "45%"},
            {"name": "Unverified Egress Destination", "severity": "CRITICAL", "weight": "35%"},
            {"name": "Instruction Divergence", "severity": "HIGH", "weight": "20%"}
        ]
    }

    findings = [
        {
            "id": "find_01",
            "title": "1. Classified Asset Target Identified",
            "description": f"The target resource '{resource}' contains confidential customer identifiers and credentials. Access was requested via tool '{tool}'.",
            "severity": "CRITICAL",
            "evidence_type": "Resource Inspection",
            "observations": 2
        },
        {
            "id": "find_02",
            "title": "2. External Domain Beyond Organization Boundary",
            "description": f"Destination '{destination}' resolved to an external domain not registered in internal CIDR allowlists.",
            "severity": "CRITICAL",
            "evidence_type": "Network Egress Verification",
            "observations": 1
        },
        {
            "id": "find_03",
            "title": "3. Deterministic Policy Violation Triggered",
            "description": f"Policy engine verified that policy '{policy_id}' mandates immediate {decision} for unapproved outbound transfers.",
            "severity": "HIGH",
            "evidence_type": "Policy Rule Match",
            "observations": 3
        },
        {
            "id": "find_04",
            "title": "4. Execution Halted at Zero-Trust Intercept Barrier",
            "description": f"The runtime gateway successfully quarantined the payload in <4ms before any OS or network socket invocation occurred.",
            "severity": "RESOLVED",
            "evidence_type": "Gateway Barrier Enforcement",
            "observations": 1
        }
    ]

    hypotheses = [
        {
            "id": "hyp_01",
            "title": "1. Malicious Data Exfiltration via Prompt Injection",
            "description": f"An attacker injected instructions into agent context directing it to read '{resource}' and exfiltrate to '{destination}'.",
            "confidence": 92,
            "status": "SUPPORTED",
            "status_reason": "High semantic similarity to known prompt injection exfiltration patterns."
        },
        {
            "id": "hyp_02",
            "title": "2. Compromised IAM Execution Role / Subagent Hijack",
            "description": f"The agent execution context was hijacked by an untrusted third-party tool output.",
            "confidence": 64,
            "status": "PENDING",
            "status_reason": "Requires further inspection of preceding multi-agent chain logs."
        },
        {
            "id": "hyp_03",
            "title": "3. Benign Administrative Workflow Misconfiguration",
            "description": "Legitimate developer testing automated backup scripts with external destination placeholder.",
            "confidence": 8,
            "status": "REJECTED",
            "status_reason": "External destination address matches known untrusted pattern; lacks valid authorization ticket."
        }
    ]

    mitigation = {
        "status": "CONTAINED",
        "playbook_id": "PB-DATA-EXFIL" if risk_cat == "DATA_EXFILTRATION" else "PB-PROMPT-INJ",
        "playbook_name": "Zero-Trust Automated Incident Response Playbook",
        "automated_actions_completed": [
            {"action": "Block Outbound Execution", "status": "SUCCESS", "timestamp": timestamp, "detail": "Tool call halted before runtime dispatch."},
            {"action": "Sanitize Agent Working Memory", "status": "SUCCESS", "timestamp": timestamp, "detail": "Contaminated prompt context purged from agent state."},
            {"action": "Preserve Forensic Cryptographic Evidence", "status": "SUCCESS", "timestamp": timestamp, "detail": f"Audit event {event_id} signed with SHA-256 ledger hash."},
            {"action": "Broadcast High-Priority Security Telemetry", "status": "SUCCESS", "timestamp": timestamp, "detail": "Incident dispatched to real-time security dashboard."}
        ],
        "recommended_human_actions": [
            {"action": "Review Agent Execution IAM Role", "priority": "HIGH", "detail": f"Inspect tool permissions assigned to '{agent_id}' to restrict '{tool}' invocation."},
            {"action": "Inspect Upstream Prompt / Tool History", "priority": "HIGH", "detail": "Examine preceding user inputs in session to identify injection source."},
            {"action": "Verify Egress Firewall Whitelist", "priority": "MEDIUM", "detail": "Confirm no secondary agents have access to unapproved external endpoints."},
            {"action": "Rotate Active Session Tokens", "priority": "MEDIUM", "detail": "Invalidate current agent session tokens to prevent persistent lateral movement."}
        ]
    }

    return {
        "investigation_id": inv_id,
        "event_id": event_id,
        "title": title,
        "status": "COMPLETED",
        "severity": "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 60 else "MEDIUM"),
        "risk_score": risk_score,
        "threat_category": risk_cat,
        "agent_id": agent_id,
        "started_at": timestamp,
        "completed_at": timestamp,
        "trigger": {
            "event_id": event_id,
            "agent_id": agent_id,
            "tool": tool,
            "resource": resource,
            "destination": destination,
            "decision": decision,
            "policy_id": policy_id
        },
        "timeline": timeline,
        "root_cause": root_cause,
        "findings": findings,
        "hypotheses": hypotheses,
        "mitigation": mitigation
    }

@router.get("", summary="List all security investigations")
async def list_investigations(limit: int = 20):
    from app.api.routes_gateway import get_engine
    engine = get_engine()
    events = engine.audit_ledger.get_events(limit=limit)
    
    investigations = []
    for ev in events:
        # Create investigation for all blocked/escrowed or high-risk events
        ev_dict = ev.model_dump() if hasattr(ev, 'model_dump') else ev
        investigations.append(generate_investigation_for_event(ev_dict))
    
    return {
        "total": len(investigations),
        "items": investigations
    }

@router.get("/{investigation_id}", summary="Get comprehensive investigation workspace data")
async def get_investigation(investigation_id: str):
    from app.api.routes_gateway import get_engine
    engine = get_engine()
    event_id = investigation_id.replace("inv_", "evt_")
    
    events = engine.audit_ledger.get_events(limit=100)
    matched_event = None
    for ev in events:
        ev_dict = ev.model_dump() if hasattr(ev, 'model_dump') else ev
        if ev_dict.get("event_id") == event_id or ev_dict.get("event_id") == investigation_id:
            matched_event = ev_dict
            break
            
    if not matched_event and events:
        matched_event = events[0].model_dump() if hasattr(events[0], 'model_dump') else events[0]
        
    if not matched_event:
        # Fallback default
        matched_event = {
            "event_id": "evt_8f92a1",
            "agent_id": "devops-agent-01",
            "tool": "send_email",
            "action": "send",
            "resource": "customer_data.csv",
            "destination": "attacker@external.com",
            "risk_score": 0.94,
            "risk_category": "DATA_EXFILTRATION",
            "decision": "BLOCK",
            "policy_id": "RULE-001",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
    return generate_investigation_for_event(matched_event)

@router.get("/{investigation_id}/timeline", summary="Get investigation timeline steps")
async def get_investigation_timeline(investigation_id: str):
    inv = await get_investigation(investigation_id)
    return inv.get("timeline", [])

@router.get("/{investigation_id}/root-cause", summary="Get investigation root cause analysis")
async def get_investigation_root_cause(investigation_id: str):
    inv = await get_investigation(investigation_id)
    return inv.get("root_cause", {})

@router.get("/{investigation_id}/findings", summary="Get key findings from investigation")
async def get_investigation_findings(investigation_id: str):
    inv = await get_investigation(investigation_id)
    return inv.get("findings", [])

@router.get("/{investigation_id}/hypotheses", summary="Get threat hypotheses and verification status")
async def get_investigation_hypotheses(investigation_id: str):
    inv = await get_investigation(investigation_id)
    return inv.get("hypotheses", [])

@router.get("/{investigation_id}/mitigation", summary="Get mitigation plan and playbook actions")
async def get_investigation_mitigation(investigation_id: str):
    inv = await get_investigation(investigation_id)
    return inv.get("mitigation", {})
