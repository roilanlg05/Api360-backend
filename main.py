from fastapi import FastAPI, Request, Depends
from app.endpoints.auth import router as auth_router
from app.endpoints.drivers import router as drivers_router
from app.middlewares.middlewares import VerifyToken
from app.models.auth_model import EmailPasswordRequestForm
from typing import Annotated
from app.services.helpers import AuthHelpers
from sqlmodel import SQLModel
from app.core.db_config import engine
from app.schemas.schemas import Users, Manager, Crew, Driver,  Organization, Location, Trip, TripHistory, Notification, Chat, ChatParticipant, Message, RefreshToken


SQLModel.metadata.create_all(engine)

auth_hpr = AuthHelpers()

users ={
    
}

app = FastAPI(title="Api360")


app.add_middleware(VerifyToken) 

app.include_router(auth_router)
app.include_router(drivers_router)

@app.get("/", tags=["Root"])
async def get_root(request: Request, authorized:bool = Depends(auth_hpr.verify_role("admin"))):
    user = request.state.user
    return {"data": user}
