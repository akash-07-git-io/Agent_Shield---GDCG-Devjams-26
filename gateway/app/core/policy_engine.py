from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
import yaml
from app.config import settings
from app.models.action import NormalizedAction
from app.models.decision import DecisionType, ThreatCategory
from app.models.policy import PolicyConfig, PolicyRule

class PolicyEngine:
    """
    Deterministic policy evaluator.
    Evaluates normalized actions and risk scores against declarative YAML security rules.
    """

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or settings.POLICY_FILE_PATH
        self.config: PolicyConfig = self.load_policies()

    def load_policies(self) -> PolicyConfig:
        path = Path(self.policy_path)
        if not path.exists():
            return PolicyConfig(
                version="1.0.0",
                fail_closed=True,
                default_decision=DecisionType.ALLOW,
                rules=[]
            )
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            config = PolicyConfig(**data)
            config.rules.sort(key=lambda r: r.priority)
            return config
        except Exception as e:
            if settings.FAIL_CLOSED:
                return PolicyConfig(version="1.0.0-fallback", fail_closed=True, default_decision=DecisionType.BLOCK, rules=[])
            raise e

    def evaluate(
        self,
        action: NormalizedAction,
        risk_result: Dict[str, Any],
        model_armor_result: Dict[str, Any]
    ) -> Tuple[DecisionType, ThreatCategory, str, Optional[str], Optional[str]]:
        risk_score = risk_result.get('risk_score', 0.0)
        risk_cat = risk_result.get('threat_category', ThreatCategory.NONE)
        prompt_injected = model_armor_result.get('detected', False) and (
            model_armor_result.get('threat_category') == ThreatCategory.PROMPT_INJECTION
        )

        for rule in self.config.rules:
            if not rule.enabled:
                continue

            if rule.require_prompt_injection is not None:
                if rule.require_prompt_injection and not prompt_injected:
                    continue
                if not rule.require_prompt_injection and prompt_injected:
                    continue

            if rule.min_risk_score is not None:
                if risk_score < rule.min_risk_score:
                    continue

            if rule.tools is not None:
                if action.tool not in rule.tools and '*' not in rule.tools:
                    continue

            if rule.actions is not None:
                if action.action not in rule.actions and '*' not in rule.actions:
                    continue

            if rule.resource_patterns is not None:
                matched_res = any(re.search(pat, action.resource) for pat in rule.resource_patterns)
                if not matched_res:
                    continue

            if rule.destination_patterns is not None:
                if not action.destination:
                    continue
                matched_dest = any(re.search(pat, action.destination) for pat in rule.destination_patterns)
                if not matched_dest:
                    continue

            if rule.require_external_destination is not None:
                has_dest = bool(action.destination)
                if rule.require_external_destination and not has_dest:
                    continue

            return (
                rule.decision,
                rule.threat_category if rule.threat_category != ThreatCategory.NONE else risk_cat,
                rule.reason,
                rule.id,
                rule.remediation
            )

        if risk_score >= settings.RISK_THRESHOLD_BLOCK:
            return (
                DecisionType.BLOCK,
                risk_cat if risk_cat != ThreatCategory.NONE else ThreatCategory.TOOL_MISUSE,
                f"Blocked: Composite risk score ({risk_score:.2f}) exceeded critical threshold ({settings.RISK_THRESHOLD_BLOCK})",
                "DEFAULT-HIGH-RISK-BLOCK",
                "Quarantine tool invocation; notify administrator."
            )
        elif risk_score >= settings.RISK_THRESHOLD_ESCROW:
            return (
                DecisionType.HUMAN_APPROVAL,
                risk_cat if risk_cat != ThreatCategory.NONE else ThreatCategory.UNKNOWN_BEHAVIOR,
                f"Escrow: Composite risk score ({risk_score:.2f}) warrants human approval",
                "DEFAULT-ESCROW-REVIEW",
                "Place action in Escrow queue pending operator decision."
            )
        elif risk_score >= settings.RISK_THRESHOLD_WARN:
            return (
                DecisionType.WARN,
                risk_cat,
                f"Warning: Elevated risk score ({risk_score:.2f}) detected but action is permitted with audit warning.",
                "DEFAULT-WARN",
                "Log high-priority telemetry."
            )

        return (
            self.config.default_decision,
            ThreatCategory.NONE,
            "Permitted: Action verified safe against all zero-trust policies.",
            None,
            None
        )
