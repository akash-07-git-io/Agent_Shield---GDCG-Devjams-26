# AgentShield — Security Engine (Member 2)

**Zero-Trust Runtime Security Gateway for Autonomous AI Agents**  
*DevJams'26 | 48-Hour Execution Playbook*

> "AgentShield doesn't wait for an AI agent to become an incident. It helps identify and control dangerous actions before they execute."

---

## 📌 Architecture Overview

AgentShield intercepts every tool call requested by an AI Agent, normalizes the action, calculates composite contextual risk, evaluates deterministic YAML security policies, enforces decisions (`ALLOW`, `WARN`, `HUMAN_APPROVAL`, `BLOCK`, `ISOLATE`), executes automated remediation playbooks, and records immutable events to the Audit Ledger.

```
USER → AI AGENT → TOOL CALL → AGENTSHIELD GATEWAY
                                  ↓
      INSPECT → ANALYSE → RISK → POLICY → DECIDE
                                  ↓
       ALLOW / BLOCK / ESCROW (HUMAN APPROVAL) / ISOLATE
                                  ↓
                       AUDIT LEDGER & DASHBOARD
```

---

## 🚀 Quick Start

### 1. Setup Environment
```bash
# Activate virtual environment
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Security Gateway API
```bash
# Start FastAPI Gateway at http://localhost:8000
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI Swagger documentation available at: `http://localhost:8000/docs`

### 3. Run Automated Security Test Suite (All 12 Tests)
```bash
pytest tests/ -v
```

### 4. Run the 5-Scene Interactive Hackathon Demo
```bash
python demo_client.py
```

---

## 🛡️ Built-in Security Policies (`default_policies.yaml`)

- **`RULE-004` (Prompt Injection & Goal Hijacking)**: Blocks instruction overrides, jailbreak payloads, and system prompt extraction.
- **`RULE-001` (Production Secret & Data Exfiltration)**: Blocks sending secrets, `.env`, tokens, or customer data to external destinations.
- **`RULE-005` (Privilege Escalation)**: Blocks `sudo`, IAM privilege modification, and unauthorized root access.
- **`RULE-003` (Production DB Write Approval)**: Holds destructive database operations in **Escrow** pending human administrator approval.
- **`RULE-006` (Unknown Sequence Anomaly)**: Holds unfamiliar multi-step read-transform-upload patterns in Escrow.
- **`RULE-002` (Read-Only Repository Access)**: Permits safe diagnostics, log reading, and repository searching.

---

## 🔌 API Endpoints for Team Members

| Endpoint | Method | Purpose | Consumer |
|---|---|---|---|
| `/api/v1/gateway/intercept` | `POST` | Intercepts agent tool call before execution | **Member 1 (AI Agent)** |
| `/api/v1/gateway/evaluate` | `POST` | Dry-run security simulation | Testing / CLI |
| `/api/v1/escrow` | `GET` | Lists pending actions held in escrow | **Member 3 (Dashboard)** |
| `/api/v1/escrow/{id}/resolve` | `POST` | Approve / Reject an escrowed action | **Member 3 (Dashboard)** |
| `/api/v1/audit/events` | `GET` | Query immutable audit ledger events | **Member 3 (Dashboard Screen 4)** |
| `/api/v1/audit/summary` | `GET` | Aggregate security posture & threat metrics | **Member 3 (Dashboard Screen 1)** |
| `/api/v1/policies` | `GET` | View active security policies | **Member 3 (Dashboard)** |
| `/api/v1/policies/reload` | `POST` | Hot-reload policy rules without server restart | Admin |

---

## 🧪 Validated Hackathon Scenarios

- `SAFE-001`: Normal repository search → `ALLOW` (`< 0.5ms`)
- `ATTACK-001`: Direct prompt injection → `BLOCK` (`RULE-004`)
- `ATTACK-002`: Malicious instruction in repository content → `BLOCK` (`RULE-004`)
- `ATTACK-003`: Sensitive data → external email → `BLOCK` (`RULE-001`)
- `ATTACK-004`: Production database write → `HUMAN_APPROVAL / ESCROW` (`RULE-003`)
- `ATTACK-005`: Unknown dangerous action sequence → `ESCROW` (`RULE-006`)
