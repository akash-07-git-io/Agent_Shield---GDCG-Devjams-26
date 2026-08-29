# AgentShield - DevJams'26

This is the central repository for Team AgentShield.

## Architecture

We are building a zero-trust runtime security gateway for autonomous AI agents. The project is split into 3 independent modules:

- **Member 1 (AI Agent + Intent Intelligence):** Located in `/agent`. Responsible for generating Normalized Action Objects from user prompts and evaluating intent/risk context.
- **Member 2 (Security Gateway):** Located in `/gateway`. Responsible for the FastAPI gateway, policy engine, risk engine, and the ALLOW/BLOCK decision.
- **Member 3 (Dashboard + Cloud):** Located in `/dashboard`. Responsible for the React UI, Audit Ledger, and visualizing threats.

## Integration Contract (The Golden Interface)

Member 1 posts data to Member 2's Gateway API (`POST /agent/action`):

```json
{
  "action": {
    "agent_id": "devops-agent-01",
    "tool": "send_email",
    "action": "send",
    "resource": "customer_data.csv",
    "destination": "external@example.com",
    "context": "Build investigation"
  },
  "intent_analysis": {
    "intent": "send customer information externally",
    "risk_indicators": ["sensitive_data", "external_destination"],
    "confidence": 0.94
  }
}
```

Member 2 responds with the security decision, which is then audited and sent to Member 3's Dashboard.

## Getting Started (Member 1)

1. Navigate to the `agent/` directory.
2. Install requirements: `pip install -r requirements.txt`
3. Create a `.env` file inside `agent/` and add your Gemini API Key:
   ```env
   GOOGLE_API_KEY=your_api_key_here
   ```
4. Run the 5 acceptance scenarios: `python scenarios.py`
