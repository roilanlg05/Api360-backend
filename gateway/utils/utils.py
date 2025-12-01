from fastapi import Request, HTTPException
import httpx
import logging
from fastapi.responses import JSONResponse
from config.settings import Settings

BASE_AUTH_URL = Settings().BASE_AUTH_URL

class Auth():
    @staticmethod
    def get_token(request: Request):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            raise ValueError("Missing authentication token")
        
        token = auth_header.split(" ", 1)[1].strip()

        if not token:
            raise ValueError("Missing authentication token")
        return token
    
    @staticmethod
    def verify_role(roles: list):
        def _dep(request: Request):
            user: dict = request.state.user_id
            user_data = user.get("metadata")
            role = user_data.get("role")
            if role not in roles:
                raise HTTPException(
                    status_code=403,
                    detail="Not Authorized: We couldn't validate the role"
                )
            return user
        return _dep
    


logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url
        self.timeout = timeout

    async def _call(self, method: str, endpoint: str, **kwargs):
        """Internal helper for making requests."""
        url = f"{self.base_url}{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(method, url, **kwargs)
            
            # Handle JSON parsing
            try:
                body = resp.json()
            except Exception:
                body = {"detail": resp.text or "Unknown error"}
                logger.error(f"Invalid JSON response from {url}: {resp.text}")
            
            return resp, body
        except httpx.ConnectError:
            logger.error(f"Auth service unreachable: {url}")
            return None, JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)
        except httpx.TimeoutException:
            logger.error(f"Auth service timeout: {url}")
            return None, JSONResponse({"detail": "Authentication timeout"}, status_code=504)
        except Exception as e:
            logger.error(f"Unexpected error calling {url}: {str(e)}")
            return None, JSONResponse({"detail": "Internal server error"}, status_code=500)

    async def get(self, endpoint: str, **kwargs):
        return await self._call("get", endpoint, **kwargs)

    async def post(self, endpoint: str, **kwargs):
        return await self._call("post", endpoint, **kwargs)

    async def put(self, endpoint: str, **kwargs):
        return await self._call("put", endpoint, **kwargs)

    async def delete(self, endpoint: str, **kwargs):
        return await self._call("delete", endpoint, **kwargs)

auth_service = AuthService(base_url=BASE_AUTH_URL)