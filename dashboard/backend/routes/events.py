from fastapi import APIRouter, HTTPException
from typing import List
from backend.models.security_event import SecurityEvent
from backend.services.gateway_client import get_live_events

router = APIRouter(prefix="/api/events", tags=["Events"])

@router.get("", response_model=List[SecurityEvent], description="Get all security events")
async def get_events():
    events_data = get_live_events()
    return [SecurityEvent(**e) for e in events_data]

@router.get("/{event_id}", response_model=SecurityEvent, description="Get details of a specific security event")
async def get_event_details(event_id: str):
    events_data = get_live_events()
    for e in events_data:
        if e.get("event_id") == event_id:
            return SecurityEvent(**e)
    raise HTTPException(status_code=404, detail="Event not found")
