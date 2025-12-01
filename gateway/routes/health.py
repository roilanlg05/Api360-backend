from fastapi import APIRouter

router = APIRouter(tags=["Health"])

@router.get("/health")
async def health_check():
    return {"status": "healthy", "service": "gateway"}

@router.get("/ready")
async def readiness_check():
    return {"status": "ready", "service": "gateway"}
