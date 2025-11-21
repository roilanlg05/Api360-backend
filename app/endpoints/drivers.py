from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from app.services.utils import AuthHelpers
from app.models.driver import CreateDriver
from app.core.db_session import SessionDep
from app.schemas.schemas import Manager, Users, Driver 
from sqlmodel import select
from sqlalchemy import or_

auth = AuthHelpers()
router = APIRouter(prefix="/v1/drivers", tags=["Drivers"])

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_driver(
    db: SessionDep,
    driver_info: CreateDriver,
    location_id: str = Query(...),
    user_data: dict = Depends(auth.verify_role(["admin"]))  # <-- lista
    ):

    email = driver_info.email.strip().lower()
    phone = (driver_info.phone or "").strip() or None
    conditions = [Users.email == email]
    if phone:
        conditions.append(Users.phone == phone)

    existing = db.exec(
        select(Users).where(or_(*conditions))  # OR entre email y phone
    ).first()
    if existing:
        if existing.email == driver_info.email:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")
        if driver_info.phone and existing.phone == driver_info.phone:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone already in use")


    hashed_password = auth.hash_password(driver_info.password)
    # Crea usuario
    user = Users(**driver_info.model_dump(exclude_unset=True))
    user.password_hash = hashed_password
    user.role = "driver"
    db.add(user)
    db.commit()
    db.refresh(user)

    # Crea driver
    driver = Driver(id=user.id, location_id=location_id)
    db.add(driver)
    db.commit()
    db.refresh(driver)

    return user.driver