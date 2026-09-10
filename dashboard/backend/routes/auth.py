from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = "SecOps Lead"

class UserInfo(BaseModel):
    user_id: str
    name: str
    email: str
    role: str
    permissions: list[str]
    session_token: str
    login_time: str

VALID_USERS = {
    "admin": {
        "user_id": "usr_secops_01",
        "name": "Alex Vance",
        "email": "secops-lead@agentshield.corp",
        "role": "Chief Information Security Officer",
        "permissions": ["all", "escrow_approve", "policy_edit", "kill_agent"]
    },
    "secops-lead@agentshield.corp": {
        "user_id": "usr_secops_01",
        "name": "Alex Vance",
        "email": "secops-lead@agentshield.corp",
        "role": "Chief Information Security Officer",
        "permissions": ["all", "escrow_approve", "policy_edit", "kill_agent"]
    },
    "investigator": {
        "user_id": "usr_forensics_02",
        "name": "Elena Rostova",
        "email": "forensics@agentshield.corp",
        "role": "Forensic Threat Investigator",
        "permissions": ["view_audit", "investigate", "download_evidence"]
    },
    "operator": {
        "user_id": "usr_operator_03",
        "name": "DevOps Lead",
        "email": "devops@agentshield.corp",
        "role": "Gateway Operator",
        "permissions": ["view_telemetry", "trigger_sim"]
    }
}

@router.post("/login", response_model=UserInfo)
async def login(req: LoginRequest):
    user_key = req.username.strip().lower()
    
    # Allow demo access with any valid user key or general fallback for flexible presentation
    user_data = VALID_USERS.get(user_key)
    if not user_data:
        # Fallback dynamic user profile for demo ease
        user_data = {
            "user_id": f"usr_{user_key[:8]}",
            "name": req.username.split("@")[0].capitalize(),
            "email": req.username if "@" in req.username else f"{req.username}@agentshield.corp",
            "role": req.role or "Security Officer",
            "permissions": ["all", "escrow_approve", "policy_edit"]
        }
        
    return UserInfo(
        user_id=user_data["user_id"],
        name=user_data["name"],
        email=user_data["email"],
        role=user_data["role"],
        permissions=user_data["permissions"],
        session_token=f"agt_jwt_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_secops_verified",
        login_time=datetime.utcnow().isoformat() + "Z"
    )

@router.get("/me")
async def get_current_user():
    return {
        "authenticated": True,
        "user": VALID_USERS["admin"],
        "gateway_status": "ONLINE"
    }

@router.post("/logout")
async def logout():
    return {"message": "Session revoked. Gateway connection closed cleanly."}
