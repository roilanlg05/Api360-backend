from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from middlewares.middlewares import VerifyToken, RequestLoggerMiddleware
from routes.auth import router as auth_router
from routes.health import router as health_router
from utils.utils import Auth
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from shared.database.db_settings import engine
from sqlmodel import SQLModel

auth = Auth()

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield

app = FastAPI(title="API Gateway", version="1.0.0", lifespan=lifespan)

limiter = Limiter(key_func=get_remote_address, default_limits=["5/minute"])

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"detail": "Too many requests. Try again later."}, status_code=429)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(VerifyToken)

app.include_router(auth_router)
app.include_router(health_router)

@app.get("/", tags=["Root"])
async def get_root(request: Request, authorized: bool = Depends(auth.verify_role("admin"))):
    user = request.state.user
    return {"data": authorized}
