import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()

print("SUPABASE_URL:", os.getenv("SUPABASE_URL"))
print("Working directory:", os.getcwd())
print(".env exists:", os.path.exists(".env"))

class Settings(BaseSettings):
    SUPABASE_URL: str = os.getenv("SUPABASE_URL")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY")
    EMAIL_SENDER: str = os.getenv("BREVO_API_KEY")

