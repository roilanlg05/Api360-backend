import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()

print("SUPABASE_URL:", os.getenv("SUPABASE_URL"))
print("Working directory:", os.getcwd())
print(".env exists:", os.path.exists(".env"))

class Settings(BaseSettings):
    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    SMTP_SERVER: str = os.getenv("BREVO_API_KEY")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    PEPPER: str = os.getenv("PEPPER")
    TOKEN_DURATION: str = os.getenv("TOKEN_DURATION")
    PUBLIC_PATHS: list[str] = [
        "/v1/auth/register",
        "/v1/auth/sign-in", 
        "/v1/auth/refresh",
        "/v1/auth/verify-email",
        "/docs",
        "/redocs",
        "/favicon.ico",
        "/openapi.json"

    ]



