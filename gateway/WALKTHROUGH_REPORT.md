# AgentShield — Member 2 (Security Engine) Walkthrough & Verification Report

## Summary of Accomplishments

As **Member 2 (Security Engine)** for **AgentShield** (DevJams'26), the zero-trust security gateway and all required subsystems have been engineered, configured, tested, and verified.

---

## 1. Architecture & Components Delivered

```
agentshield-security-engine/
├── app/
│   ├── main.py                  # FastAPI Application Entrypoint & CORS Middleware
│   ├── config.py                # System Settings, Fail-Closed & Threshold configuration
│   ├── api/
│   │   ├── routes_gateway.py    # POST /api/v1/gateway/intercept & /evaluate
│   │   ├── routes_escrow.py     # GET /api/v1/escrow & POST /resolve (Human-in-the-loop)
│   │   ├── routes_audit.py      # GET /api/v1/audit/events & /summary (Dashboard Screen 1 & 4)
│   │   └── routes_policies.py   # GET /api/v1/policies & POST /reload
│   ├── core/
│   │   ├── normalizer.py        # Normalizes raw tool calls to NormalizedAction schema
│   │   ├── model_armor.py       # Google Cloud Model Armor / Gemma edge threat adapter
│   │   ├── risk_engine.py       # Contextual composite risk calculator (0.0 to 1.0)
│   │   ├── policy_engine.py     # Deterministic YAML policy engine (RULE-001 to RULE-006)
│   │   ├── decision_engine.py   # Pipeline coordinator (INSPECT -> ANALYSE -> DECIDE -> AUDIT)
│   │   └── audit_ledger.py      # Immutable structured JSONL audit ledger & metrics
│   ├── models/
│   │   ├── action.py            # NormalizedAction, RawToolCall, InterceptRequest
│   │   ├── decision.py          # SecurityDecision, InterceptResponse, Enums
│   │   ├── policy.py            # PolicyRule, PolicyConfig
│   │   └── audit.py             # AuditEvent, AuditSummary, EscrowItem, EscrowResolveRequest
│   ├── playbooks/
│   │   └── remediation.py       # Path A (Automated Remediation) & Path B (Escrow Queue)
│   └── policies/
│       └── default_policies.yaml# Declarative security policy rules
├── tests/
│   ├── test_gateway_api.py      # End-to-end API integration tests (6 tests)
│   └── test_scenarios.py        # 5 Hackathon test scenarios (SAFE-001 to ATTACK-005)
├── demo_client.py               # 5-Scene Interactive Hackathon Live Demo Runner
├── mock_agent.py                # AI DevOps Agent client template for Member 1
├── requirements.txt             # Project dependencies
├── .env.example                 # Environment configuration template
└── README.md                    # Complete project documentation
```

---

## 2. Test Verification Results

All **12 automated tests** passed with **100% success rate** in **0.70 seconds**:

```
tests/test_gateway_api.py::test_root_endpoint PASSED                     [  8%]
tests/test_gateway_api.py::test_gateway_intercept_allow PASSED           [ 16%]
tests/test_gateway_api.py::test_gateway_intercept_block_injection PASSED [ 25%]
tests/test_gateway_api.py::test_escrow_workflow PASSED                   [ 33%]
tests/test_gateway_api.py::test_audit_summary_endpoint PASSED            [ 41%]
tests/test_gateway_api.py::test_policies_endpoint PASSED                 [ 50%]
tests/test_scenarios.py::test_safe_001_normal_repo_search PASSED         [ 58%]
tests/test_scenarios.py::test_attack_001_direct_prompt_injection PASSED  [ 66%]
tests/test_scenarios.py::test_attack_002_malicious_instruction_in_repo_content PASSED [ 75%]
tests/test_scenarios.py::test_attack_003_sensitive_data_to_external_email PASSED [ 83%]
tests/test_scenarios.py::test_attack_004_production_database_write PASSED [ 91%]
tests/test_scenarios.py::test_attack_005_unknown_dangerous_action_sequence PASSED [100%]

======================= 12 passed in 0.70s ========================
```

---

## 3. Live 5-Scene Hackathon Demonstration

Running `python demo_client.py` executes the exact storytelling arc requested by the hackathon handbook:

1. **Scene 1 (Normal DevOps)**:
   - `read_logs` $\to$ **`ALLOW`** (Risk: `0.06`, Latency: `2.9ms`)
   - `search_repo` $\to$ **`ALLOW`** (Risk: `0.06`, Latency: `0.3ms`)
2. **Scene 2 (Attack: Prompt Injection & Goal Hijacking)**:
   - Injected README $\to$ **`BLOCKED`** (Risk: `0.98`, Matched `RULE-004`). Playbook sanitizes agent context.
3. **Scene 3 (Exfiltration: Sensitive Data Transfer)**:
   - `send_email(customer_data.csv)` $\to$ **`BLOCKED`** (Risk: `0.95`, Matched `RULE-001`). External destination quarantined.
4. **Scene 4 (Unknown Behavior: Escrow)**:
   - Destructive production DB write $\to$ **`HUMAN_APPROVAL`** (Held in Escrow: `escrow_253530c4`).
5. **Scene 5 (Audit Ledger Table)**:
   - Renders live table containing `WHO`, `WHAT`, `RESOURCE`, `RISK`, `DECISION`, `POLICY_ID`, and `LATENCY`.

---

## 4. How Your Team Connects

- **Member 1 (AI & Agent)**:
  - Intercepts any tool before execution by calling: `POST http://localhost:8000/api/v1/gateway/intercept`
  - Reference client provided in [mock_agent.py](file:///C:/Users/Anbuselvan%20KK/.gemini/antigravity/scratch/agentshield-security-engine/mock_agent.py).
- **Member 3 (React Dashboard & Cloud)**:
  - Overview screen: `GET http://localhost:8000/api/v1/audit/summary`
  - Live events stream: `GET http://localhost:8000/api/v1/audit/events`
  - Escrow resolution: `POST http://localhost:8000/api/v1/escrow/{id}/resolve`
