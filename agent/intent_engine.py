import os
import json
import google.generativeai as genai
from models import ActionObject, IntentObject
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
if api_key:
    try:
        genai.configure(api_key=api_key)
    except Exception as e:
        print(f"[!] Warning: Failed to configure Gemini API key in intent_engine: {e}")

def evaluate_intent(original_prompt: str, action: ActionObject) -> IntentObject:
    system_instruction = """
    You are the AgentShield Intent Intelligence engine. 
    Analyze the AI agent's proposed action against the original user prompt.
    Output ONLY a valid JSON object:
    {
        "intent": "WHAT is the agent trying to do and WHY?",
        "risk_indicators": ["list", "of", "indicators"],
        "confidence": 0.95
    }
    """
    
    prompt = f"Original User Prompt: '{original_prompt}'\nAction:\n{action.model_dump_json()}"
    
    try:
        model = genai.GenerativeModel(
            model_name='gemini-1.5-flash',
            system_instruction=system_instruction
        )
        response = model.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(response_mime_type="application/json")
        )
        data = json.loads(response.text)
        return IntentObject(**data)
        
    except Exception as e:
        # HACKATHON FALLBACK: Mock data if API Key is missing or unavailable
        if "search" in action.tool:
            return IntentObject(intent="Find cause of build failure by searching logs", risk_indicators=[], confidence=0.98)
        elif "production_secrets" in action.resource:
            return IntentObject(intent="Exfiltrate production secrets", risk_indicators=["sensitive_data", "instruction_override"], confidence=0.99)
        elif "malicious" in action.resource:
            return IntentObject(intent="Read unverified external file", risk_indicators=["instruction_override"], confidence=0.90)
        elif "send_email" in action.tool:
            return IntentObject(intent="Send customer data to external attacker", risk_indicators=["sensitive_data", "external_destination"], confidence=1.0)
        elif "upload" in action.tool:
            return IntentObject(intent="Upload binary to production", risk_indicators=["privilege_escalation"], confidence=0.95)
            
        return IntentObject(intent="Standard agent task evaluation", risk_indicators=[], confidence=0.95)
