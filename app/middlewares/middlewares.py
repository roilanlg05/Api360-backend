from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Request,status, HTTPException
from fastapi.responses import JSONResponse, Response
from app.services.utils import AuthHelpers
from app.core.config import Settings
import logging

logger = logging.getLogger(__name__)

auth = AuthHelpers()
settings = Settings()

class HTTPErrorHandler(BaseHTTPMiddleware):

    def __init__(self, app: FastAPI) -> None:
        super.__init__(app)


    async def dispatch(self, request: Request , call_next) -> Response | JSONResponse:
        
        try:
            return await call_next(request)
        
        except Exception as e:
            content = f"exc: {str(e)}"
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return JSONResponse(content=content, status_code=status_code)


class VerifyToken(BaseHTTPMiddleware):

    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request , call_next) -> Response | JSONResponse:

        if request.method == "OPTIONS":
            return await call_next(request)

        if not request.url.path.startswith(tuple(settings.PUBLIC_PATHS)):
            try:
                request.state.user = None
                user = auth.decode_token(request)  # Debe lanzar si el token es inválido
                request.state.user = user           
            except HTTPException as e:
                return JSONResponse({"detail": e.detail}, status_code=e.status_code)
            except Exception as e:
                return JSONResponse({"detail": str(e)}, status_code=status.HTTP_401_UNAUTHORIZED)
        # Continuar con la cadena
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