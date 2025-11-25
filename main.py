from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.endpoints.auth import router as auth_router
from app.endpoints.drivers import router as drivers_router
from app.endpoints.locations import router as locations_router
from app.endpoints.trips import router as trips_router
from app.middlewares.middlewares import VerifyToken, RequestLoggerMiddleware
from typing import Annotated
from app.services.utils import AuthHelpers
from sqlmodel import SQLModel
from app.core.db_config import engine
from app.schemas.schemas import Users, Manager, Crew, Driver,  Organization, Location, Trip, TripHistory, Notification, Chat, ChatParticipant, Message, RefreshToken


SQLModel.metadata.create_all(engine)

auth = AuthHelpers()

users ={
    
}

app = FastAPI(title="Api360")


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",           # Frontend local (React/Next.js)
        "http://192.168.0.133:3000",       # Frontend en red local
        "http://192.168.0.133:3030"
    ],
    allow_credentials=True,  # Permitir cookies/auth headers
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],     # Permitir los métodos (GET, POST, PUT, DELETE.)
    allow_headers=["*"],     # Permitir todos los headers
)
app.add_middleware(VerifyToken)
app.add_middleware(RequestLoggerMiddleware)

app.include_router(auth_router)
app.include_router(drivers_router)
app.include_router(locations_router)
app.include_router(trips_router)



@app.get("/", tags=["Root"])
async def get_root(request: Request, authorized:bool = Depends(auth.verify_role("admin"))):
    user = request.state.user
    return {"data": authorized}
