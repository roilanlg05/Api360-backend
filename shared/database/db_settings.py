from shared.config.settings import BaseAppSettings
from typing import Annotated, AsyncGenerator
from fastapi import Depends
from urllib.parse import quote_plus
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

settings = BaseAppSettings()

_pwd = quote_plus(settings.POSTGRES_PASSWORD or "")
URL = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{_pwd}@{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"

# Async engine
engine = create_async_engine(URL, future=True)

# Async session factory
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# Async dependency to inject DB sessions
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session

AsyncSessionDep = Annotated[AsyncSession, Depends(get_db)]

