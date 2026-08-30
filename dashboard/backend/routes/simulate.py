from fastapi import APIRouter
from backend.models.security_event import SimulateRequest
from backend.services.gateway_client import inject_scenario_event

router = APIRouter(prefix="/api/simulate", tags=["Simulator"])

@router.post("/trigger", description="Trigger simulated agent action attack for live judge demos")
async def trigger_simulation(request: SimulateRequest):
    event = inject_scenario_event(request.scenario_id)
    return {
        "status": "INJECTED",
        "scenario": request.scenario_id,
        "event": event
    }
