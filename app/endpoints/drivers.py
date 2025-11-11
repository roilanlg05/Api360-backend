from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse, RedirectResponse   
from app.services.helpers import AuthHelpers

auth_hpr = AuthHelpers()

router = APIRouter(prefix="/v1/drivers", tags=["Drivers"])

@router.get("/picture")
async def get_pict():
    return FileResponse("/home/roilan/Downloads/TradePost Interface for Traders.png")

@router.get("/{org_id}")
async def get_drivers(
    loc_id: str = Query(max_length=15),
    org_id: str = Path(max_length=15),
    user = Depends(auth_hpr.verify_role("crew_member")),  # ahora sí: solo verify_role y verify_token
    active: bool | None = None,
    limit: int = 10,
    offset: int = 0,
):
    # user contiene lo devuelto por verify_token
    data = {"drivers": [], "requested_by": user.get("email"), "location: ": loc_id}
    return JSONResponse(content=data)
