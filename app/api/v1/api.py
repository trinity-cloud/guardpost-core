from fastapi import APIRouter

from app.api.v1.endpoints import auth, scan, findings

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(scan.router, prefix="/scans", tags=["AWS Scanning"])
api_router.include_router(findings.router, prefix="/findings", tags=["Security Findings"])
