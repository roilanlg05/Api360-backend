from fastapi import APIRouter, Request, Cookie, Header
from fastapi.responses import JSONResponse
from pydantic import EmailStr
from utils.utils import Auth, auth_service
from slowapi import Limiter
from slowapi.util import get_remote_address
from shared.models.user_model import CreateManager, UserData, EmailPasswordRequestForm, CreateCrewMember, PasswordUpdate, NewPassword

limiter = Limiter(key_func=get_remote_address)

auth = Auth()

router = APIRouter(prefix="/v1/auth", tags=["Authentication"])

@router.post("/register/crew-member")
@limiter.limit("3/minute")
async def register_crew_member(
    user_data: CreateCrewMember,
    request: Request
    ) -> dict:

    resp, body = await auth_service.post('/register/crew-member', json=user_data.model_dump())

    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)
    return jsonr


@router.post("/register/manager")
@limiter.limit("3/minute")
async def manager(
    user_data: CreateManager,
    request: Request
    ) -> dict:

    resp, body = await auth_service.post('/register/manager', json=user_data.model_dump())

    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)
    return jsonr

@router.post("/verify-data")
async def verify_data(
    user_data: UserData
    ) -> dict:

    resp, body = await auth_service.post('/verify-data', json=user_data.model_dump())
    
    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)
    return jsonr

@router.post("/sign-in")
@limiter.limit("1/minute")
async def sign_in(
    user_data: EmailPasswordRequestForm,
    request: Request
    ) -> dict:

    resp, body = await auth_service.post('/sign-in', json=user_data.model_dump())

    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)

    for cookie in resp.headers.get_list("set-cookie"):
        jsonr.headers.append("set-cookie", cookie)
    return jsonr

@router.post("/sign-out") # ANADIR LOGICA PARA DETECTAR SI YA EL USUARIO YA HIZO LOGOUT
@limiter.limit("1/minute")
async def sign_out(
    request: Request,
    user_id: str = Header(alias="x-user-id")
    
    ) -> dict:

    resp, body = await auth_service.post('/sign-out', headers={"x-user-id": user_id})

    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)

    for cookie in ["refresh_token", "expires_at"]:
        jsonr.delete_cookie(cookie)
    return jsonr

@router.post("/refresh")
@limiter.limit("3/minute")
async def refresh(
    request: Request,
    refresh: str | None = Cookie(default=None, alias="refresh_token")
    ) -> dict:
        
    resp, body = await auth_service.post("/refresh", cookies={"refresh_token": refresh})

    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)
       
    for cookie in resp.headers.get_list("set-cookie"):
        jsonr.headers.append("set-cookie", cookie)
    return jsonr

@router.put("/change-password")
@limiter.limit("30/minute")
async def change_password(
    user_data: PasswordUpdate, 
    request: Request,
    user_id: str = Header(alias="x-user-id")
    ) -> dict:

    resp, body = await auth_service.put("/change-password", json=user_data.model_dump(), headers={"x-user-id": user_id})
   
    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)

    for cookie in ["refresh_token", "expires_at"]:
        jsonr.delete_cookie(cookie)
    return jsonr

@router.get("/verify-email")
@limiter.limit("1/minute")
async def verify_email(
    token:str,
    request: Request
    ) -> dict:
        
    resp, body = await auth_service.get('/verify-email', params={"token": token})

    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)
    return jsonr

@router.post("/forgot-password")
@limiter.limit("30/minute")
async def forgot_password(
    email:EmailStr,
    request: Request
    ) -> dict:
        
    resp, body = await auth_service.post("/forgot-password", params={"email": email})
   
    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)
    return jsonr

@router.post("/reset-password")
@limiter.limit("3/minute")
async def reset_password(
    token: str, 
    new_password: NewPassword,
    request: Request
    ) -> dict:

    resp, body = await auth_service.post("/reset-password", params={"token": token}, json=new_password.model_dump())
    
    if isinstance(body, JSONResponse):
        return body
    
    jsonr = JSONResponse(body, status_code=resp.status_code)

    for cookie in ["refresh_token", "expires_at"]:
        jsonr.delete_cookie(cookie)
    return jsonr
