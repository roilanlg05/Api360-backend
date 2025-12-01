import os
from dotenv import load_dotenv
from shared.config.settings import BaseAppSettings

load_dotenv()

class Settings(BaseAppSettings):
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    PEPPER: str = os.getenv("PEPPER")
    
    class Config:
        env_file = "../.env"
        extra = "ignore"