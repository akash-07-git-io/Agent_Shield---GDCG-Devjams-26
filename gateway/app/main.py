import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import api_router
from app.config import settings

app = FastAPI(
    title="AgentShield Security Engine",
    description="Zero-Trust Runtime Security Gateway for Autonomous AI Agents (DevJams'26)",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = (time.perf_counter() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    return response

@app.get("/", tags=["System"])
async def root():
    return {
        "service": "AgentShield Security Gateway",
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "docs": "/docs",
        "mantra": "INTERCEPT. ANALYSE. DECIDE. PROTECT."
    }

@app.post("/agent/action", tags=["System"])
async def agent_action(request: Request):
    from app.api.routes_gateway import get_engine
    engine = get_engine()
    data = await request.json()
    decision, _ = engine.process(data, simulate=False)
    return decision

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=settings.PORT, reload=True)
