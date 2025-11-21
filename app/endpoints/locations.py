from app.models.location import CreateLocation
from app.core.db_session import SessionDep
from app.schemas.schemas import Location
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from app.services.utils import AuthHelpers
from app.core.db_session import SessionDep


auth = AuthHelpers()

router = APIRouter(prefix="/v1/locations", tags=["Locations"])

@router.post("/")
async def create_location(
    db: SessionDep,
    location_info: CreateLocation,
    user_data: dict = Depends(auth.verify_role(["admin"]))
    ):

    
    location = Location(**location_info.model_dump(exclude_unset=True))
    location.organization_id = user_data.get("metadata").get("organization_id")
    
    db.add(location)
    db.commit()
    db.refresh(location)
    
    return user_data