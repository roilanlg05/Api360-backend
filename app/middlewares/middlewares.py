from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Request,status, HTTPException
from fastapi.responses import JSONResponse, Response
from app.services.helpers import AuthHelpers
from app.core.config import Settings

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

    # Aplica solo a endpoints de drivers (ajusta si quieres otro scope)
        if not request.url.path.startswith(tuple(settings.PUBLIC_PATHS)):
            try:
                request.state.user = None
                user = auth.decode_token(request)  # Debe lanzar si el token es inválido
                request.state.user = user["user_data"]
            except HTTPException as e:
                return JSONResponse({"detail": e.detail}, status_code=e.status_code)
            except Exception as e:
                return JSONResponse({"detail": str(e)}, status_code=status.HTTP_401_UNAUTHORIZED)
        # Continuar con la cadena
        response = await call_next(request)
        return response