from fastapi import APIRouter
from typing import Dict, Any
from backend.services.gateway_client import get_system_health

router = APIRouter(prefix="/api/system", tags=["System Health"])

@router.get("/health", description="Get operational status and component health")
async def system_health():
    return get_system_health()
