from datetime import datetime, timezone
import time
from typing import Any, Dict, Optional, Tuple
import uuid
from app.config import settings
from app.core.audit_ledger import AuditLedger
from app.core.model_armor import ModelArmorAdapter
from app.core.normalizer import ActionNormalizer
from app.core.policy_engine import PolicyEngine
from app.core.risk_engine import RiskEngine
from app.models.action import NormalizedAction, RawToolCall
from app.models.audit import AuditEvent, EscrowItem
from app.models.decision import DecisionType, InterceptResponse, SecurityDecision, ThreatCategory
from app.playbooks.remediation import RemediationPlaybooks

class DecisionEngine:
    """
    Core orchestration pipeline for AgentShield Security Gateway.
    Enforces the handbook architecture:
    INSPECT (Model Armor) -> ANALYSE (Risk Engine) -> POLICY (Policy Engine) -> DECIDE (Path A/B) -> AUDIT
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        model_armor: Optional[ModelArmorAdapter] = None,
        audit_ledger: Optional[AuditLedger] = None
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.model_armor = model_armor or ModelArmorAdapter()
        self.audit_ledger = audit_ledger or AuditLedger()

    def process(self, raw_input: Any, simulate: bool = False) -> Tuple[SecurityDecision, InterceptResponse]:
        start_time = time.perf_counter()
        event_id = f"evt_{uuid.uuid4().hex[:8]}"

        try:
            # 1. Normalize
            action: NormalizedAction = ActionNormalizer.normalize(raw_input)

            # 2. Model Armor / Threat Scanning
            model_armor_res = self.model_armor.inspect(action)

            # 3. Risk Calculation
            risk_res = self.risk_engine.calculate_risk(action, model_armor_res)
            risk_score = risk_res.get('risk_score', 0.0)
            threat_cat = risk_res.get('threat_category', ThreatCategory.NONE)

            # 4. Policy Evaluation
            decision_type, final_threat_cat, reason, policy_id, policy_remediation = self.policy_engine.evaluate(
                action=action,
                risk_result=risk_res,
                model_armor_result=model_armor_res
            )

            # 5. Path A (Remediation) vs Path B (Escrow)
            remediation_text = policy_remediation
            escrow_id = None

            if decision_type in [DecisionType.BLOCK, DecisionType.ISOLATE]:
                playbook_res = RemediationPlaybooks.execute_playbook(final_threat_cat, action, reason)
                remediation_text = playbook_res.get('remediation', policy_remediation)
            elif decision_type == DecisionType.HUMAN_APPROVAL:
                escrow_item = self.audit_ledger.create_escrow_item(
                    action=action,
                    risk_score=risk_score,
                    threat_category=final_threat_cat,
                    reason=reason,
                    policy_id=policy_id
                )
                escrow_id = escrow_item.escrow_id
                playbook_res = RemediationPlaybooks.execute_playbook(ThreatCategory.UNKNOWN_BEHAVIOR, action, reason)
                remediation_text = f"Action held in escrow ({escrow_id}). Awaiting administrator approval."

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            self.risk_engine.record_action(action.agent_id, action)

            sec_decision = SecurityDecision(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                agent_id=action.agent_id,
                user_id=action.user_id,
                tool=action.tool,
                action=action.action,
                resource=action.resource,
                destination=action.destination,
                risk_score=risk_score,
                risk_category=final_threat_cat,
                decision=decision_type,
                reason=reason,
                policy_id=policy_id,
                model_version=self.model_armor.model_version,
                latency_ms=round(elapsed_ms, 2),
                remediation=remediation_text,
                escrow_id=escrow_id
            )

            self.audit_ledger.record_decision(sec_decision, action)

            allowed = decision_type in [DecisionType.ALLOW, DecisionType.WARN]
            response = InterceptResponse(
                allowed=allowed,
                decision=decision_type,
                risk_score=risk_score,
                threat_category=final_threat_cat,
                reason=reason,
                event_id=event_id,
                latency_ms=round(elapsed_ms, 2),
                remediation=remediation_text,
                escrow_id=escrow_id,
                action_result={"executed": True, "message": f"Tool {action.tool} executed successfully"} if allowed and not simulate else None
            )

            return sec_decision, response

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            fallback_decision = SecurityDecision(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                agent_id="unknown",
                user_id="unknown",
                tool="unknown",
                action="unknown",
                resource="unknown",
                destination=None,
                risk_score=1.0,
                risk_category=ThreatCategory.TOOL_MISUSE,
                decision=DecisionType.BLOCK if settings.FAIL_CLOSED else DecisionType.ALLOW,
                reason=f"Fail-closed: Internal Gateway processing exception: {str(e)}",
                policy_id="FAIL_CLOSED_HANDLER",
                model_version=self.model_armor.model_version,
                latency_ms=round(elapsed_ms, 2),
                remediation="Execution blocked due to security engine error."
            )
            response = InterceptResponse(
                allowed=False,
                decision=DecisionType.BLOCK,
                risk_score=1.0,
                threat_category=ThreatCategory.TOOL_MISUSE,
                reason=f"Fail-Closed Error: {str(e)}",
                event_id=event_id,
                latency_ms=round(elapsed_ms, 2),
                remediation="Execution blocked due to internal security engine failure."
            )
            return fallback_decision, response
