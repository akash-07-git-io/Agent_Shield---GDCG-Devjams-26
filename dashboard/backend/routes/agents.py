from fastapi import APIRouter
from typing import List, Dict, Any
from backend.services.gateway_client import get_agents

router = APIRouter(prefix="/api/agents", tags=["Agent Fleet"])

@router.get("", description="Get connected AI agents fleet information")
async def list_agents():
    return get_agents()
