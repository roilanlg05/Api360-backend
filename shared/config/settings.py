from pydantic_settings import BaseSettings
from typing import Optional

class BaseAppSettings(BaseSettings):
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: str = "5432"
    POSTGRES_DB: str = "api360"
    POSTGRES_USER: str = "hashdown"
    POSTGRES_PASSWORD: str = ""
    BREVO_KEY: Optional[str] = None
    TOKEN_DURATION: str = "5"
    JWT_SECRET_KEY: Optional[str] = None
    PEPPER: Optional[str] = None
    PUBLIC_PATHS: list[str] = [
        "/v1/auth/register",
        "/v1/auth/sign-in", 
        "/v1/auth/refresh",
        "/v1/auth/verify-email",
        "/v1/auth/forgot-password",
        "/v1/auth/reset-password",
        "/docs",
        "/redoc",
        "/favicon.ico",
        "/openapi.json",
        "/v1/auth/register/organization",
        "/health",
        "/ready",
    ]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"