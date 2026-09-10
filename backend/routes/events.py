from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.models.security_event import SecurityEvent
from backend.services.mock_data import mock_events
from backend.services import gateway_client

router = APIRouter(prefix="/api/events", tags=["Events"])

@router.get("", description="Get all security events")
async def get_events(use_mock: bool = Query(False, description="Use mock data")):
    if use_mock:
        return mock_events
    return await gateway_client.get_audit_events()

@router.get("/{event_id}", description="Get details of a specific security event")
async def get_event_details(event_id: str, use_mock: bool = Query(False, description="Use mock data")):
    if use_mock:
        for event in mock_events:
            if event.event_id == event_id:
                return event
        raise HTTPException(status_code=404, detail="Event not found")
        
    events = await gateway_client.get_audit_events()
    for event in events:
        if event.get("event_id") == event_id:
            return event
    raise HTTPException(status_code=404, detail="Event not found in Member 2 audit logs")
