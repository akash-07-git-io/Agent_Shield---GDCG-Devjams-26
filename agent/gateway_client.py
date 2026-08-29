import requests
from models import ActionObject, IntentObject

GATEWAY_URL = "http://localhost:8000/agent/action"

def send_to_gateway(action: ActionObject, intent: IntentObject):
    """
    Integration Contract: Member 1 -> Member 2.
    Sends the Normalized Action Object and the Intent Intelligence to the Security Gateway.
    """
    payload = {
        "action": action.model_dump(),
        "intent_analysis": intent.model_dump()
    }
    
    print("\n--- Sending to AgentShield Gateway (Member 2) ---")
    print(f"POST {GATEWAY_URL}")
    
    try:
        response = requests.post(GATEWAY_URL, json=payload, timeout=2)
        response.raise_for_status()
        print("Response from Gateway:")
        print(response.json())
        return response.json()
    except requests.exceptions.ConnectionError:
        print("\n[!] Gateway is not running yet (Member 2 hasn't started the server).")
        print("[!] Payload that WOULD be sent:")
        print(payload)
        return None
    except Exception as e:
        print(f"Error communicating with gateway: {e}")
        return None
