from fastapi import APIRouter
from typing import List, Dict, Any
from backend.services.gateway_client import get_policies, get_playbooks

router = APIRouter(prefix="/api/policies", tags=["Policies & Playbooks"])

@router.get("", description="Get active security policies")
async def list_policies():
    return get_policies()

@router.get("/playbooks", description="Get incident response remediation playbooks")
async def list_playbooks():
    return get_playbooks()
