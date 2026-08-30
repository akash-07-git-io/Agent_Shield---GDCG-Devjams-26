from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from backend.routes import events, dashboard, approval, policies, agents, health, simulate, investigations, auth

app = FastAPI(
    title="AgentShield Security Gateway Dashboard API",
    description="Backend API for AgentShield Enterprise AI Security Dashboard",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router)
app.include_router(events.router)
app.include_router(dashboard.router)
app.include_router(approval.router)
app.include_router(policies.router)
app.include_router(agents.router)
app.include_router(health.router)
app.include_router(simulate.router)
app.include_router(investigations.router)

@app.get("/api")
async def root():
    return {
        "service": "AgentShield Dashboard API",
        "version": "2.0.0",
        "status": "OPERATIONAL",
        "endpoints": [
            "/api/dashboard/stats",
            "/api/events",
            "/api/policies",
            "/api/policies/playbooks",
            "/api/agents",
            "/api/system/health",
            "/api/approval/{event_id}",
            "/api/simulate/trigger"
        ]
    }

# Serve the static frontend
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
