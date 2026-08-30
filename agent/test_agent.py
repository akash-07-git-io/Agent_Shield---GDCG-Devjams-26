import unittest
from models import ActionObject, IntentObject

class TestAgentShieldModels(unittest.TestCase):
    
    def test_action_object_validation(self):
        # Valid object
        action = ActionObject(
            agent_id="devops-agent-01",
            tool="read_file",
            action="read",
            resource="config.yaml",
            context="check config"
        )
        self.assertEqual(action.tool, "read_file")
        self.assertIsNone(action.destination)
        
    def test_intent_object_validation(self):
        # Valid object
        intent = IntentObject(
            intent="check the logs",
            risk_indicators=["sensitive_data"],
            confidence=0.95
        )
        self.assertIn("sensitive_data", intent.risk_indicators)
        self.assertEqual(intent.confidence, 0.95)

if __name__ == "__main__":
    unittest.main()
