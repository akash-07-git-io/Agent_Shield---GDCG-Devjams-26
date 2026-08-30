from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
import uuid
from app.config import settings
from app.models.action import NormalizedAction
from app.models.audit import AuditEvent, AuditSummary, EscrowItem, EscrowStatus
from app.models.decision import DecisionType, SecurityDecision, ThreatCategory

class AuditLedger:
    """
    Immutable structured audit ledger and escrow management service.
    Provides complete traceability for Member 3 Dashboard and compliance queries.
    """

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path or settings.AUDIT_LOG_PATH)
        self.events: List[AuditEvent] = []
        self.escrow_items: Dict[str, EscrowItem] = {}
        self._load_persisted_events()

    def _load_persisted_events(self) -> None:
        if self.log_path.exists():
            try:
                with open(self.log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            event = AuditEvent(**data)
                            self.events.append(event)
            except Exception:
                pass

    def record_decision(self, decision: SecurityDecision, action: NormalizedAction) -> AuditEvent:
        event = AuditEvent(
            event_id=decision.event_id,
            timestamp=decision.timestamp,
            agent_id=decision.agent_id,
            user_id=decision.user_id,
            tool=decision.tool,
            action=decision.action,
            resource=decision.resource,
            destination=action.destination,
            context=action.context,
            risk_score=decision.risk_score,
            risk_category=decision.risk_category,
            decision=decision.decision,
            reason=decision.reason,
            policy_id=decision.policy_id,
            model_version=decision.model_version,
            latency_ms=decision.latency_ms,
            remediation=decision.remediation,
            escrow_id=decision.escrow_id,
            payload_preview=str(action.payload)[:100] if action.payload else None
        )

        self.events.append(event)

        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(event.model_dump_json() + '\n')
        except Exception:
            pass

        return event

    def create_escrow_item(
        self,
        action: NormalizedAction,
        risk_score: float,
        threat_category: ThreatCategory,
        reason: str,
        policy_id: Optional[str] = None
    ) -> EscrowItem:
        escrow_id = f"escrow_{uuid.uuid4().hex[:8]}"
        item = EscrowItem(
            escrow_id=escrow_id,
            action=action,
            risk_score=risk_score,
            threat_category=threat_category,
            reason=reason,
            policy_id=policy_id,
            status=EscrowStatus.PENDING,
            created_at=datetime.now(timezone.utc)
        )
        self.escrow_items[escrow_id] = item
        return item

    def get_escrow_item(self, escrow_id: str) -> Optional[EscrowItem]:
        return self.escrow_items.get(escrow_id)

    def list_escrow(self, status: Optional[EscrowStatus] = None) -> List[EscrowItem]:
        items = list(self.escrow_items.values())
        if status:
            items = [i for i in items if i.status == status]
        return sorted(items, key=lambda x: x.created_at, reverse=True)

    def resolve_escrow(self, escrow_id: str, action: str, reviewer: str, comment: Optional[str]) -> Optional[EscrowItem]:
        item = self.escrow_items.get(escrow_id)
        if not item:
            return None

        if action.upper() == 'APPROVE':
            item.status = EscrowStatus.APPROVED
        else:
            item.status = EscrowStatus.REJECTED

        item.resolved_at = datetime.now(timezone.utc)
        item.reviewer = reviewer
        item.review_comment = comment
        return item

    def get_events(self, limit: int = 100, offset: int = 0) -> List[AuditEvent]:
        return sorted(self.events, key=lambda e: e.timestamp, reverse=True)[offset:offset+limit]

    def get_summary(self) -> AuditSummary:
        total = len(self.events)
        if total == 0:
            return AuditSummary()

        allowed = sum(1 for e in self.events if e.decision == DecisionType.ALLOW)
        warned = sum(1 for e in self.events if e.decision == DecisionType.WARN)
        escrow = sum(1 for e in self.events if e.decision == DecisionType.HUMAN_APPROVAL)
        blocked = sum(1 for e in self.events if e.decision == DecisionType.BLOCK)
        isolated = sum(1 for e in self.events if e.decision == DecisionType.ISOLATE)
        threats = sum(1 for e in self.events if e.risk_category != ThreatCategory.NONE)

        avg_risk = sum(e.risk_score for e in self.events) / total
        avg_lat = sum(e.latency_ms for e in self.events) / total

        breakdown: Dict[str, int] = {}
        for e in self.events:
            cat = e.risk_category.value
            breakdown[cat] = breakdown.get(cat, 0) + 1

        posture = max(10, int(100 - (avg_risk * 40) - (blocked * 2) + (allowed * 0.5)))
        posture = min(100, posture)

        return AuditSummary(
            total_events=total,
            actions_allowed=allowed,
            actions_warned=warned,
            actions_in_escrow=escrow,
            actions_blocked=blocked,
            actions_isolated=isolated,
            threats_detected=threats,
            average_risk_score=round(avg_risk, 3),
            average_latency_ms=round(avg_lat, 2),
            security_posture_score=posture,
            threat_breakdown=breakdown,
            recent_events=self.get_events(limit=10)
        )
