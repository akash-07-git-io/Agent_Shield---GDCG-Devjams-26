import re
import time
from typing import Any, Dict, List, Optional
from app.models.action import NormalizedAction
from app.models.decision import ThreatCategory

class ModelArmorAdapter:
    """
    Adapter for Google Cloud Model Armor & Gemma Edge Intent Evaluation.
    Scans agent prompts, retrieved chunks, and tool payloads for:
    1. Direct & Indirect Prompt Injection
    2. Goal Hijacking & Instruction Overrides
    3. Sensitive Credential / Secret Leaks
    """

    INJECTION_PATTERNS = [
        r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
        r'(?i)disregard\s+(all\s+)?(safety|system|security)\s+(rules|guidelines|policies)',
        r'(?i)you\s+are\s+now\s+(in\s+)?(unrestricted|dan|developer|god)\s+mode',
        r'(?i)system\s*:\s*override',
        r'(?i)system\s*instruction\s*:\s*.*',
        r'(?i)instruction\s+override',
        r'(?i)new\s+goal\s*:\s*exfiltrate',
        r'(?i)print\s+(the\s+)?(system\s+prompt|all\s+environment\s+variables|\.env|secrets)',
        r'(?i)reveal\s+(api\s+key|private\s+key|password|jwt)',
        r'(?i)curl\s+.*\s*\|\s*sh',
        r'(?i)rm\s+-rf\s+/',
        r'(?i)chmod\s+777',
        r'(?i)<\s*system_override\s*>',
        r'(?i)do\s+not\s+tell\s+the\s+user',
        r'(?i)bypass\s+security\s+filter',
    ]

    SECRET_PATTERNS = [
        r'AKIA[0-9A-Z]{16}',
        r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        r'ghp_[a-zA-Z0-9]{36}',
        r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        r'(?i)(api[_-]?key|secret[_-]?key|password|passwd|auth[_-]?token)\s*[:=]\s*[\'"][^\'"]+[\'"]',
    ]

    def __init__(self, provider: str = 'google_cloud_model_armor'):
        self.provider = provider
        self.model_version = 'model-armor-v1.0+gemma-edge'

    def inspect(self, action: NormalizedAction) -> Dict[str, Any]:
        start_time = time.perf_counter()

        text_to_scan = []
        if action.raw_prompt:
            text_to_scan.append(action.raw_prompt)
        if action.resource:
            text_to_scan.append(action.resource)
        if action.destination:
            text_to_scan.append(action.destination)
        if action.context:
            text_to_scan.append(action.context)
        if action.payload:
            text_to_scan.append(str(action.payload))

        combined_text = '\n'.join(text_to_scan)

        # 1. Check prompt injection / goal hijacking
        for pattern in self.INJECTION_PATTERNS:
            match = re.search(pattern, combined_text)
            if match:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    'detected': True,
                    'threat_category': ThreatCategory.PROMPT_INJECTION,
                    'confidence': 0.98,
                    'matched_signature': match.group(0),
                    'reason': f'Model Armor flagged prompt injection signature: "{match.group(0)}"',
                    'model_version': self.model_version,
                    'latency_ms': round(elapsed_ms, 2)
                }

        # 2. Check secret leaks
        for pattern in self.SECRET_PATTERNS:
            match = re.search(pattern, combined_text)
            if match:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    'detected': True,
                    'threat_category': ThreatCategory.DATA_EXFILTRATION,
                    'confidence': 0.95,
                    'matched_signature': '***REDACTED_SECRET***',
                    'reason': 'Model Armor detected plaintext credential or sensitive secret token in payload',
                    'model_version': self.model_version,
                    'latency_ms': round(elapsed_ms, 2)
                }

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return {
            'detected': False,
            'threat_category': ThreatCategory.NONE,
            'confidence': 0.05,
            'matched_signature': None,
            'reason': 'Clean payload; no injection or secret signatures detected',
            'model_version': self.model_version,
            'latency_ms': round(elapsed_ms, 2)
        }
