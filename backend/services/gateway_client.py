import os
import httpx
from fastapi import HTTPException
from dotenv import load_dotenv

load_dotenv()

GATEWAY_URL = os.getenv("AGENTSHIELD_GATEWAY_URL", "http://127.0.0.1:8000")
timeout = httpx.Timeout(10.0, connect=5.0)

async def _make_request(method: str, endpoint: str, **kwargs):
    url = f"{GATEWAY_URL}{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Member 2 Security Gateway is unreachable")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Member 2 Security Gateway timed out")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Member 2 Error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def get_audit_events():
    return await _make_request("GET", "/api/v1/audit/events")

async def get_audit_summary():
    return await _make_request("GET", "/api/v1/audit/summary")

async def get_escrow():
    return await _make_request("GET", "/api/v1/escrow")

async def get_escrow_details(escrow_id: str):
    return await _make_request("GET", f"/api/v1/escrow/{escrow_id}")

async def resolve_escrow(escrow_id: str, action: str, reviewer: str, comment: str):
    payload = {
        "action": action,
        "reviewer": reviewer,
        "comment": comment
    }
    return await _make_request("POST", f"/api/v1/escrow/{escrow_id}/resolve", json=payload)

async def get_policies():
    return await _make_request("GET", "/api/v1/policies")
