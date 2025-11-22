import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()

class Settings(BaseSettings):
    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    BREVO_KEY: str = os.getenv("BREVO_KEY")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    PEPPER: str = os.getenv("PEPPER")
    TOKEN_DURATION: str = os.getenv("TOKEN_DURATION")
    PUBLIC_PATHS: list[str] = [
        "/v1/auth/register",
        "/v1/auth/sign-in", 
        "/v1/auth/refresh",
        "/v1/auth/verify-email",
        "/v1/auth/forgot-password",
        "/v1/auth/reset-password",
        "/docs",
        "/redocs",
        "/favicon.ico",
        "/openapi.json",
    ]



