from supabase import create_client, Client
from app.core.config import Settings
settings = Settings()


url: str = settings.SUPABASE_URL
key: str = settings.SUPABASE_KEY

supabase: Client = create_client(url, key)