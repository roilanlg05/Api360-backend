from fastapi import APIRouter, Depends, HTTPException
from app.services.auth import verify_role

router = APIRouter(prefix="/v1/drivers", tags=["Drivers"])

@router.get("/{org_id}")
async def get_drivers(
    org_id: str,
    loc_id: str,
    user = Depends(verify_role("crew_member")),  # ahora sí: solo verify_role y verify_token
    active: bool | None = None,
    limit: int = 10,
    offset: int = 0,
):
    # user contiene lo devuelto por verify_token
    return {"drivers": [], "requested_by": user.get("email"), "location: ": loc_id}