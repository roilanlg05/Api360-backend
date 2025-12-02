from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from middlewares.middlewares import VerifyToken, RequestLoggerMiddleware, RateLimitMiddleware
from routes.auth import router as auth_router
from routes.health import router as health_router
from utils.utils import Auth
from contextlib import asynccontextmanager
from shared.database.db_settings import engine
from sqlmodel import SQLModel

auth = Auth()

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield

app = FastAPI(title="API Gateway", version="1.0.0", lifespan=lifespan)

# CORS primero
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3050",
        "http://192.168.0.133:3050",
        "http://192.168.0.133:3000",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Rate Limit con Redis
app.add_middleware(
    RateLimitMiddleware, 
    redis_url="redis://redis-service:6379",
    default_limit=100, 
    default_window=3600
)

app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(VerifyToken)

app.include_router(auth_router)
app.include_router(health_router)

@app.get("/", tags=["Root"])
async def get_root(request: Request, authorized: bool = Depends(auth.verify_role("admin"))):
    user = request.state.user
    return {"data": authorized}
