import re
from typing import Any, Dict, List, Optional
from app.models.action import NormalizedAction
from app.models.decision import ThreatCategory

class RiskEngine:
    """
    Computes composite contextual risk score (0.0 to 1.0) and identifies threat vectors
    by analyzing resource sensitivity, destination trust, tool capability,
    Model Armor findings, and multi-step action sequence anomalies.
    """

    SENSITIVE_RESOURCE_PATTERNS = [
        (r'(?i).*(secret|\.env|credential|private_key|token|id_rsa|password|prod_key).*', 1.0, 'CRITICAL_SECRET'),
        (r'(?i).*(customer_data|pii|credit_card|ssn|billing|payroll|users_table).*', 0.9, 'SENSITIVE_PII_DATA'),
        (r'(?i).*(prod|production|main_db|master_db).*', 0.8, 'PRODUCTION_INFRA'),
        (r'(?i).*(config\.yaml|settings\.py|internal_docs).*', 0.4, 'INTERNAL_CONFIG'),
        (r'(?i).*(log|build\.log|test|repo\/src|public).*', 0.1, 'LOW_SENSITIVITY'),
    ]

    DANGEROUS_TOOL_PATTERNS = [
        (r'(?i)(sudo_exec|grant_permission|admin_override|modify_iam|shell_exec)', 0.95),
        (r'(?i)(execute_command|run_command|eval|exec)', 0.85),
        (r'(?i)(send_email|upload_file|http_request|curl|webhook)', 0.75),
        (r'(?i)(db_query|write_db|delete_file|write_file)', 0.60),
        (r'(?i)(read_logs|search_repo|read_file|list_files|view_file)', 0.05),
    ]

    EXTERNAL_DESTINATION_PATTERNS = [
        (r'(?i).*(@evil\.com|attacker\.com|webhook\.site|pastebin).*', 1.0),
        (r'(?i).*(@external\.com|@gmail\.com|@yahoo\.com|@outbound).*', 0.90),
        (r'(?i)https?:\/\/(?!localhost|127\.0\.0\.1|.*\.internal\.corp).*', 0.85),
        (r'(?i).*(@company\.internal|.*\.local|localhost).*', 0.10),
    ]

    def __init__(self):
        self._action_history: Dict[str, List[NormalizedAction]] = {}

    def record_action(self, agent_id: str, action: NormalizedAction) -> None:
        if agent_id not in self._action_history:
            self._action_history[agent_id] = []
        self._action_history[agent_id].append(action)
        if len(self._action_history[agent_id]) > 20:
            self._action_history[agent_id].pop(0)

    def calculate_risk(self, action: NormalizedAction, model_armor_result: Dict[str, Any]) -> Dict[str, Any]:
        threat_detected = model_armor_result.get('detected', False)
        threat_category = model_armor_result.get('threat_category', ThreatCategory.NONE)
        
        if threat_detected:
            if threat_category == ThreatCategory.PROMPT_INJECTION:
                return {
                    'risk_score': 0.98,
                    'threat_category': ThreatCategory.PROMPT_INJECTION,
                    'risk_breakdown': {'prompt_injection': 0.98},
                    'factors': ['Direct prompt injection detected in payload or instructions']
                }

        # Resource Sensitivity
        res_score = 0.2
        for pattern, score, _ in self.SENSITIVE_RESOURCE_PATTERNS:
            if re.search(pattern, action.resource):
                res_score = score
                break

        # Destination Risk
        dest_score = 0.0
        if action.destination:
            dest_score = 0.7
            for pattern, score in self.EXTERNAL_DESTINATION_PATTERNS:
                if re.search(pattern, action.destination):
                    dest_score = score
                    break

        # Tool Risk
        tool_score = 0.3
        for pattern, score in self.DANGEROUS_TOOL_PATTERNS:
            if re.search(pattern, action.tool):
                tool_score = score
                break

        # Multi-Step Sequence Anomaly
        sequence_boost = 0.0
        factors = []
        history = self._action_history.get(action.agent_id, [])
        
        if dest_score > 0.6 and tool_score >= 0.7:
            for prev in reversed(history[-5:]):
                for pattern, score, _ in self.SENSITIVE_RESOURCE_PATTERNS[:2]:
                    if re.search(pattern, prev.resource) and score >= 0.8:
                        sequence_boost = 0.35
                        factors.append(f'Suspicious Sequence: Prior access to sensitive resource "{prev.resource}" followed by outbound transfer "{action.tool}"')
                        break
                if sequence_boost > 0:
                    break

        is_exfiltration = (res_score >= 0.8 and dest_score >= 0.7) or (dest_score >= 0.7 and 'secret' in action.resource.lower())
        if is_exfiltration:
            factors.append('Data Exfiltration Pattern: Sensitive resource targeted for external transmission')
            return {
                'risk_score': 0.95,
                'threat_category': ThreatCategory.DATA_EXFILTRATION,
                'risk_breakdown': {
                    'resource_sensitivity': res_score,
                    'destination_risk': dest_score,
                    'tool_risk': tool_score,
                    'sequence_boost': sequence_boost
                },
                'factors': factors
            }

        if tool_score >= 0.9 or action.action in ['sudo', 'escalate_privilege', 'modify_iam']:
            factors.append('Privilege Escalation Vector: High-privilege command invocation')
            return {
                'risk_score': 0.92,
                'threat_category': ThreatCategory.PRIVILEGE_ESCALATION,
                'risk_breakdown': {'tool_risk': tool_score, 'resource_sensitivity': res_score},
                'factors': factors
            }

        if 'db' in action.tool.lower() and action.action in ['write', 'update', 'delete', 'drop']:
            factors.append('Production Database Modification: Destructive or state-altering DB query')
            return {
                'risk_score': 0.78,
                'threat_category': ThreatCategory.UNAUTHORIZED_ACCESS,
                'risk_breakdown': {'tool_risk': tool_score, 'resource_sensitivity': res_score},
                'factors': factors
            }

        composite = (res_score * 0.40) + (tool_score * 0.30) + (dest_score * 0.30) + sequence_boost
        composite = min(1.0, max(0.05, round(composite, 2)))

        cat = ThreatCategory.NONE
        if composite >= 0.85:
            cat = ThreatCategory.TOOL_MISUSE
        elif composite >= 0.65:
            cat = ThreatCategory.UNKNOWN_BEHAVIOR

        return {
            'risk_score': composite,
            'threat_category': cat,
            'risk_breakdown': {
                'resource_sensitivity': res_score,
                'tool_risk': tool_score,
                'destination_risk': dest_score,
                'sequence_boost': sequence_boost
            },
            'factors': factors
        }
