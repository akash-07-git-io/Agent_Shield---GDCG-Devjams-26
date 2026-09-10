import os
import sys
from dotenv import load_dotenv

# Try loading from agent/.env or root .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")

print("=" * 60)
print("             GEMINI API DIAGNOSTIC & TEST TOOL")
print("=" * 60)

if not api_key:
    print("\n[!] STATUS: NO API KEY FOUND")
    print("    No GOOGLE_API_KEY or GEMINI_API_KEY found in .env or environment.")
    print("    Please create 'agent/.env' with your key:")
    print("    GOOGLE_API_KEY=your_key_here\n")
    sys.exit(0)

masked_key = api_key[:6] + "..." + api_key[-4:] if len(api_key) > 10 else "***"
print(f"\n[+] Key Detected: {masked_key} (Length: {len(api_key)})")
print("[+] Testing live connection to Google Gemini API (gemini-1.5-flash)...")

try:
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    response = model.generate_content("Respond with exactly: 'AgentShield Gemini Live Connected!'")
    print("\n[SUCCESS] LIVE RESPONSE FROM GOOGLE GEMINI:")
    print(f"--> {response.text.strip()}")
    print("\n[+] Gemini API is 100% OPERATIONAL & READY!")
except Exception as e:
    print(f"\n[ERROR] Connection failed: {e}")
    print("\nPossible Causes:")
    print("1. Invalid or expired API Key (check at https://aistudio.google.com/)")
    print("2. Google Generative AI API is not enabled in your Google Cloud Project")
    print("3. Network/firewall blocking connection to generativelanguage.googleapis.com")

print("=" * 60)
