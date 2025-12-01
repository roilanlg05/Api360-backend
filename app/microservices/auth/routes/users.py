from fastapi import APIRouter, HTTPException, Depends
from shared.database.db_settings import AsyncSessionDep
from models.user_model import ManagerResponse
from services.utils import Auth

router = APIRouter(prefix="/v1/users")

auth = Auth()

@router.get("/manager", response_model=ManagerResponse)
async def get_user(session: AsyncSessionDep, user_data: dict = Depends(auth.verify_role["admin", "manager"])) -> ManagerResponse:
   
    user = await auth.get_current_user(session, user)

    return ManagerResponse(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        phone=user.phone,
        profile_pic=user.profile_pic,
        organization_id=user.manager.organization_id,
        email_verified_at=user.email_verified_at,
        created_at=user.created_at
        )
    

    
    