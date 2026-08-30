import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "AgentShield Security Engine"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    FAIL_CLOSED: bool = True
    POLICY_FILE_PATH: str = str(Path(__file__).parent / "policies" / "default_policies.yaml")
    AUDIT_LOG_PATH: str = str(Path(__file__).parent.parent / "audit_events.jsonl")
    
    RISK_THRESHOLD_BLOCK: float = 0.85
    RISK_THRESHOLD_ESCROW: float = 0.65
    RISK_THRESHOLD_WARN: float = 0.40
    
    MODEL_ARMOR_ENABLED: bool = True
    MODEL_ARMOR_PROVIDER: str = "google_cloud_model_armor"
    MODEL_ARMOR_VERSION: str = "model-armor-v1.0+gemma-edge"
    
    CORS_ORIGINS: list[str] = ["*"]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
