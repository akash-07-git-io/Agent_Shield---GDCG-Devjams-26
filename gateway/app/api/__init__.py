from fastapi import APIRouter
from app.api.routes_gateway import router as gateway_router
from app.api.routes_escrow import router as escrow_router
from app.api.routes_audit import router as audit_router
from app.api.routes_policies import router as policies_router

api_router = APIRouter()
api_router.include_router(gateway_router)
api_router.include_router(escrow_router)
api_router.include_router(audit_router)
api_router.include_router(policies_router)
