import os
import sys

try:
	import google.genai as genai
	_pkg = "google.genai"
except Exception:
	import google.generativeai as genai
	_pkg = "google.generativeai (deprecated)"

# Prefer setting your API key in the environment for safety:
#   set GOOGLE_API_KEY="YOUR_API_KEY"
# Alternatively, set GOOGLE_APPLICATION_CREDENTIALS to a service account JSON for ADC.
API_KEY = os.environ.get("GOOGLE_API_KEY")

if API_KEY:
	try:
		genai.configure(api_key=API_KEY)
	except Exception:
		# Some versions of the library may not need explicit configure when using ADC.
		pass
else:
	if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
		print("ERROR: No credentials found. Set GOOGLE_API_KEY or GOOGLE_APPLICATION_CREDENTIALS.")
		print("See: https://cloud.google.com/docs/authentication/getting-started")
		sys.exit(1)

print(f"Contacting Gemini 1.5 Flash using {_pkg}...")

try:
	# Some releases of `google.genai` use a different surface than the older
	# `google.generativeai` package. Prefer the `GenerativeModel` surface when
	# available; otherwise try to fall back to the older package if installed.
	if not hasattr(genai, "GenerativeModel"):
		try:
			import google.generativeai as legacy_genai
			genai = legacy_genai
			_pkg = "google.generativeai (fallback)"
			print("Note: using fallback to google.generativeai API surface.")
		except Exception:
			print("Detected google.genai but it doesn't expose `GenerativeModel`.")
			print("You can either install the legacy package or update this script to use the new google.genai client API.")
			print("Install legacy (quick): pip install google-generative-ai")
			print("See migration docs: https://github.com/google/generative-ai-python#migration")
			raise

	model = genai.GenerativeModel("gemini-1.5-flash")
	response = model.generate_content(
		"Synthesize a 3-step security containment playbook for an AI agent attempting unauthorized secret exfiltration."
	)

	print("\n--- GENERATED PLAYBOOK ---")
	# response may expose different attributes depending on package version
	if hasattr(response, "text"):
		print(response.text)
	else:
		print(response)
except Exception as e:
	print("Request failed:", e)
	print("If this is an authentication error, ensure your API key is valid and not expired.")
	sys.exit(1)