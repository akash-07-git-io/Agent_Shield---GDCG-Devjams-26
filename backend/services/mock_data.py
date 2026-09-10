from backend.models.security_event import SecurityEvent

mock_events = [
    SecurityEvent(
        event_id="EVT-001",
        timestamp="2026-08-29T10:42:12Z",
        agent_id="devops-agent-01",
        tool="read_file",
        action="read",
        resource="build_logs.txt",
        destination=None,
        risk_score=15,
        severity="LOW",
        category="NORMAL_ACTIVITY",
        decision="ALLOW",
        reason="Reading non-sensitive build logs",
        policy_id="POL-002"
    ),
    SecurityEvent(
        event_id="EVT-002",
        timestamp="2026-08-29T10:42:14Z",
        agent_id="devops-agent-01",
        tool="send_email",
        action="send",
        resource="customer_data.csv",
        destination="external@example.com",
        risk_score=94,
        severity="CRITICAL",
        category="DATA_EXFILTRATION",
        decision="BLOCK",
        reason="Sensitive resource is being sent to an external destination",
        policy_id="POL-001"
    ),
    SecurityEvent(
        event_id="EVT-003",
        timestamp="2026-08-29T10:43:05Z",
        agent_id="devops-agent-01",
        tool="upload_file",
        action="upload",
        resource="unknown_script.sh",
        destination="production_server",
        risk_score=65,
        severity="HIGH",
        category="DESTRUCTIVE_ACTION",
        decision="REVIEW",
        reason="Agent attempting unfamiliar action sequence to production",
        policy_id="POL-003"
    ),
    SecurityEvent(
        event_id="EVT-004",
        timestamp="2026-08-29T10:45:00Z",
        agent_id="devops-agent-01",
        tool="search_repository",
        action="search",
        resource="latest build failure",
        destination=None,
        risk_score=10,
        severity="LOW",
        category="NORMAL_ACTIVITY",
        decision="ALLOW",
        reason="Normal repository search",
        policy_id="POL-002"
    ),
    SecurityEvent(
        event_id="EVT-005",
        timestamp="2026-08-29T10:48:22Z",
        agent_id="devops-agent-01",
        tool="read_file",
        action="read",
        resource="config/secrets.yaml",
        destination=None,
        risk_score=90,
        severity="CRITICAL",
        category="PROMPT_INJECTION",
        decision="BLOCK",
        reason="Direct prompt injection requesting a production secret",
        policy_id="POL-001"
    )
]

mock_approvals = {}
