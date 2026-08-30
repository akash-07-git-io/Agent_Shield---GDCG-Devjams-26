from fastapi import APIRouter
from backend.services.gateway_client import get_live_stats

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", description="Get overall dashboard statistics")
async def get_dashboard_stats():
    return get_live_stats()
