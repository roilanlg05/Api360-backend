import os
from dotenv import load_dotenv
from shared.config.settings import BaseAppSettings

load_dotenv()

class Settings(BaseAppSettings):
    BASE_AUTH_URL: str = "http://auth-service:8000/v1/auth"
