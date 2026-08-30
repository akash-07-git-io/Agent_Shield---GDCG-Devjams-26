import logging
from typing import Any, Dict, Optional
from app.models.action import NormalizedAction
from app.models.decision import ThreatCategory

logger = logging.getLogger('agentshield.playbooks')

class RemediationPlaybooks:
    """
    Automated Path A (Known Threats) & Path B (Unknown Threats) Playbook Handlers.
    """

    @classmethod
    def execute_playbook(
        cls,
        threat_category: ThreatCategory,
        action: NormalizedAction,
        reason: str
    ) -> Dict[str, Any]:
        if threat_category in [ThreatCategory.PROMPT_INJECTION, ThreatCategory.GOAL_HIJACKING]:
            return cls.playbook_prompt_injection(action, reason)
        elif threat_category == ThreatCategory.DATA_EXFILTRATION:
            return cls.playbook_data_exfiltration(action, reason)
        elif threat_category == ThreatCategory.PRIVILEGE_ESCALATION:
            return cls.playbook_privilege_escalation(action, reason)
        elif threat_category == ThreatCategory.UNKNOWN_BEHAVIOR:
            return cls.playbook_unknown_behavior(action, reason)
        else:
            return {
                'playbook': 'DEFAULT_ISOLATE',
                'remediation': 'Action execution halted; standard audit recorded.',
                'action_taken': 'BLOCK_AND_LOG'
            }

    @classmethod
    def playbook_prompt_injection(cls, action: NormalizedAction, reason: str) -> Dict[str, Any]:
        logger.warning(f"[PLAYBOOK: PROMPT_INJECTION] Rejecting contaminated input for agent={action.agent_id}")
        return {
            'playbook': 'PLAYBOOK_PROMPT_INJECTION_DEFENSE',
            'remediation': 'Contaminated instruction rejected. Agent memory context sanitized and isolated.',
            'action_taken': 'REJECT_INSTRUCTION',
            'isolated_agent': action.agent_id,
            'details': {
                'injection_source': action.raw_prompt[:60] if action.raw_prompt else 'tool payload',
                'quarantine_status': 'ACTIVE'
            }
        }

    @classmethod
    def playbook_data_exfiltration(cls, action: NormalizedAction, reason: str) -> Dict[str, Any]:
        logger.warning(f"[PLAYBOOK: DATA_EXFILTRATION] Blocking destination {action.destination} for resource {action.resource}")
        return {
            'playbook': 'PLAYBOOK_EXFILTRATION_DEFENSE',
            'remediation': f'External destination blocked ("{action.destination}"). Outbound egress quarantined.',
            'action_taken': 'BLOCK_DESTINATION_AND_EGRESS',
            'blocked_destination': action.destination,
            'protected_resource': action.resource
        }

    @classmethod
    def playbook_privilege_escalation(cls, action: NormalizedAction, reason: str) -> Dict[str, Any]:
        logger.warning(f"[PLAYBOOK: PRIVILEGE_ESCALATION] Revoking permissions for tool {action.tool}")
        return {
            'playbook': 'PLAYBOOK_PRIVILEGE_REVOCATION',
            'remediation': f'Execution permission revoked for tool "{action.tool}". Agent flagged for admin review.',
            'action_taken': 'REVOKE_PERMISSION_AND_FLAG',
            'restricted_tool': action.tool,
            'restricted_action': action.action
        }

    @classmethod
    def playbook_unknown_behavior(cls, action: NormalizedAction, reason: str) -> Dict[str, Any]:
        logger.warning(f"[PLAYBOOK: UNKNOWN_BEHAVIOR] Placing action into Escrow queue")
        return {
            'playbook': 'PLAYBOOK_ESCROW_ENFORCEMENT',
            'remediation': 'Action placed in secure Escrow. Execution blocked until human operator approves.',
            'action_taken': 'QUEUE_IN_ESCROW',
            'escrow_action': f"{action.tool}:{action.action} on {action.resource}"
        }
