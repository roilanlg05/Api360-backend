from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
from config.settings import Settings
import logging
import time
import redis.asyncio as redis

logger = logging.getLogger(__name__)
settings = Settings()

# Orígenes permitidos (compartido entre middlewares)
ALLOWED_ORIGINS = [
    "http://localhost:3050",
    "http://192.168.0.133:3050",
    "http://192.168.0.133:3000",
    "http://localhost:3000",
    "http://192.168.0.148:3000",
]


def get_cors_headers(request: Request) -> dict:
    """Genera headers CORS basados en el origen de la request."""
    origin = request.headers.get("origin", "")
    
    if origin in ALLOWED_ORIGINS:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
    return {}


class HTTPErrorHandler(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response | JSONResponse:
        try:
            return await call_next(request)
        except Exception as e:
            logger.error(f"Unhandled error: {str(e)}")
            return JSONResponse(
                content={"detail": "Internal server error"},
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                headers=get_cors_headers(request)
            )


class VerifyToken(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response | JSONResponse:
        if request.method == "OPTIONS":
            return await call_next(request)

        if not request.url.path.startswith(tuple(settings.PUBLIC_PATHS)):
            token = request.headers.get("Authorization")
            if not token or not token.startswith("Bearer "):
                return JSONResponse(
                    {"detail": "Missing or invalid Authorization header"}, 
                    status_code=401,
                    headers=get_cors_headers(request)
                )

            headers = {"Authorization": token}

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"{settings.BASE_AUTH_URL}/verify-token", headers=headers)
                
                if resp.status_code != 200:
                    return JSONResponse(
                        {"detail": "Invalid token"}, 
                        status_code=401,
                        headers=get_cors_headers(request)
                    )
                
                data = resp.json()
                if not data.get("valid"):
                    return JSONResponse(
                        {"detail": "Invalid token"}, 
                        status_code=401,
                        headers=get_cors_headers(request)
                    )
                request.state.user_data = data
                
                user_id = data.get("user", {}).get("id")
                if user_id:
                    request.scope["headers"].append((b"x-user-id", str(user_id).encode()))

            except httpx.ConnectError:
                logger.error("Auth service unreachable")
                return JSONResponse(
                    {"detail": "Authentication service unavailable"}, 
                    status_code=503,
                    headers=get_cors_headers(request)
                )
            except httpx.TimeoutException:
                logger.error("Auth service timeout")
                return JSONResponse(
                    {"detail": "Authentication timeout"}, 
                    status_code=504,
                    headers=get_cors_headers(request)
                )
            except Exception as e:
                logger.error(f"Token verification error: {str(e)}")
                return JSONResponse(
                    {"detail": "Token verification failed"}, 
                    status_code=500,
                    headers=get_cors_headers(request)
                )
        
        response = await call_next(request)
        return response


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        url = request.url.path
        user_agent = request.headers.get("user-agent", "unknown")
        referer = request.headers.get("referer", "unknown")
        origin = request.headers.get("origin", "unknown")
        
        logger.info(f"""
        📥 Incoming Request:
        - IP: {client_ip}
        - Method: {method}
        - Path: {url}
        - User-Agent: {user_agent}
        - Origin: {origin}
        - Referer: {referer}
        """)
        
        response = await call_next(request)
        
        logger.info(f"📤 Response Status: {response.status_code}")
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware de rate limiting con Redis.
    """
    
    def __init__(
        self, 
        app, 
        redis_url: str = "redis://redis-service:6379",
        default_limit: int = 100, 
        default_window: int = 3600
    ):
        super().__init__(app)
        self.redis_url = redis_url
        self.default_limit = default_limit
        self.default_window = default_window
        self._redis: redis.Redis | None = None
        
        # Límites personalizados por ruta
        self.route_limits = {
            "/v1/auth/register/crew-member": (3, 3600),
            "/v1/auth/register/manager": (3, 3600),
            "/v1/auth/sign-in": (5, 60),
            "/v1/auth/forgot-password": (1, 300),
            "/v1/auth/reset-password": (3, 3600),
            "/v1/auth/refresh": (10, 60),
            "/v1/auth/verify-email": (5, 300),
            "/v1/auth/verify-data": (3, 60),
            "/health": (1000, 60),
        }
    
    async def _get_redis(self) -> redis.Redis:
        """Obtiene o crea conexión a Redis."""
        if self._redis is None:
            self._redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
        return self._redis
    
    def _get_limit_for_path(self, path: str) -> tuple[int, int]:
        """Obtiene el límite y ventana para una ruta específica."""
        if path in self.route_limits:
            return self.route_limits[path]
        
        for route_pattern, limits in self.route_limits.items():
            if path.startswith(route_pattern.rstrip("/")):
                return limits
        
        return self.default_limit, self.default_window
    
    def _get_client_ip(self, request: Request) -> str:
        """Obtiene la IP real del cliente."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        path = request.url.path
        method = request.method
        
        key = f"ratelimit:{client_ip}:{method}:{path}"
        limit, window = self._get_limit_for_path(path)
        
        try:
            r = await self._get_redis()
            current = await r.incr(key)
            
            if current == 1:
                await r.expire(key, window)
            
            ttl = await r.ttl(key)
            
            if current > limit:
                return JSONResponse(
                    {
                        "detail": "Too many requests. Try again later.",
                        "retry_after": ttl
                    },
                    status_code=429,
                    headers={
                        **get_cors_headers(request),
                        "Retry-After": str(ttl)
                    }
                )
            
            response = await call_next(request)
            
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current))
            response.headers["X-RateLimit-Reset"] = str(ttl)
            
            return response
            
        except redis.ConnectionError:
            logger.warning("Redis unavailable for rate limiting, allowing request")
            return await call_next(request)
        except Exception as e:
            logger.error(f"Rate limit error: {e}")
            return await call_next(request)