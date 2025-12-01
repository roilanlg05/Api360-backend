from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
from config.settings import Settings
import logging

logger = logging.getLogger(__name__)
settings = Settings()

class HTTPErrorHandler(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)  # ← Corregido: super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response | JSONResponse:
        try:
            return await call_next(request)
        except Exception as e:
            logger.error(f"Unhandled error: {str(e)}")
            content = {"detail": "Internal server error"}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return JSONResponse(content=content, status_code=status_code)

class VerifyToken(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response | JSONResponse:
        if request.method == "OPTIONS":
            return await call_next(request)

        if not request.url.path.startswith(tuple(settings.PUBLIC_PATHS)):
            token = request.headers.get("Authorization")
            if not token or not token.startswith("Bearer "):
                return JSONResponse({"detail": "Missing or invalid Authorization header"}, status_code=401)

            headers = {"Authorization": token}

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"{settings.BASE_AUTH_URL}/verify-token", headers=headers)
                
                if resp.status_code != 200:
                    return JSONResponse({"detail": "Invalid token"}, status_code=401)
                
                # Extrae claims y setea en request.state
                data = resp.json()
                if not data.get("valid"):
                    return JSONResponse({"detail": "Invalid token"}, status_code=401)
                request.state.user_data = data
                
                # Añade user_id en header interno para downstream
                user_id = data.get("user", {}).get("id")
                if user_id:
                    request.scope["headers"].append((b"x-user-id", str(user_id).encode()))

            except httpx.ConnectError:
                logger.error("Auth service unreachable")
                return JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)
            except httpx.TimeoutException:
                logger.error("Auth service timeout")
                return JSONResponse({"detail": "Authentication timeout"}, status_code=504)
            except Exception as e:
                logger.error(f"Token verification error: {str(e)}")
                return JSONResponse({"detail": "Token verification failed"}, status_code=500)
        
        response = await call_next(request)
        return response

class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # ✅ Información del cliente
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        url = request.url.path
        user_agent = request.headers.get("user-agent", "unknown")
        referer = request.headers.get("referer", "unknown")
        origin = request.headers.get("origin", "unknown")
        
        # ✅ Log de la petición logger.info
        print(f"""
        📥 Incoming Request:
        - IP: {client_ip}
        - Method: {method}
        - Path: {url}
        - User-Agent: {user_agent}
        - Origin: {origin}
        - Referer: {referer}
        """)
        
        # Continuar con la petición
        response = await call_next(request)
        
        # ✅ Log de la respuesta logger.info
        print(f"📤 Response Status: {response.status_code}")
        
        return response