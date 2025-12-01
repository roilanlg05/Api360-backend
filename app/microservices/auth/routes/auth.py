from services.smtp import get_confirmation_email_template, get_password_reset_email_template, send_email
from shared.models.user_model import CreateManager, CreateCrewMember, UserData, PasswordUpdate, EmailPasswordRequestForm, NewPassword
from shared.schemas.schemas import Users, Manager, Crew, Organization
from fastapi import APIRouter, HTTPException, status, Response, Cookie, Request, Header
from services.utils import Utils, Auth
from datetime import timedelta
from shared.database.db_settings import AsyncSessionDep
from fastapi.responses import JSONResponse
from config.settings import Settings
from sqlmodel import select
from jose import JWTError, jwt
from pydantic import EmailStr
import secrets
import httpx

utils = Utils()
auth = Auth()
settings = Settings()

BASE_URL = "http://192.168.0.133:3000"  # Frontend URL (mantener)
BASE_API_URL = "http://localhost:8000/v1/auth"  # Auth service se llama a sí mismo

router = APIRouter(prefix="/v1/auth", tags=["Auth"])

@router.post("/register/crew-member", status_code=status.HTTP_201_CREATED)
async def register_crew_member(
    user_data: CreateCrewMember, 
    session: AsyncSessionDep
    ) -> dict:

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            data = {
                "email": user_data.email
            }
            resp = await client.post(f"{BASE_API_URL}/verify-data", json=data)
    except httpx.ConnectError:
        #logger.error("Auth service unreachable")
        return JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)
    except httpx.TimeoutException:
        #logger.error("Auth service timeout")
        return JSONResponse({"detail": "Authentication timeout"}, status_code=504)

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail"))

    hashed_pass = auth.hash_password(user_data.password)

    try:
        user = Users(
            email=user_data.email.lower(),
            password_hash=hashed_pass,
            role="crew"
        )
        session.add(user)
        await session.flush()

        crew = Crew(id=user.id, airline=user_data.airline)
        session.add(crew)
        await session.commit()
        await session.refresh(user)
            
        metadata = {
            "email": user.email,
            "purpose" : "email_verification"
        }
            
        token = auth.encode_token(str(user.id), metadata, expires_in=timedelta(hours=24)) 
        confirmation_url = f"{BASE_URL}/auth/verify-email/?token={token['access_token']}"
        html_content = get_confirmation_email_template(confirmation_url)

        await send_email(
            user.email,
            "Confirm Your Api360 Account",
            html_content,
            confirmation_url
        )

        return {"message": "User registred succefull. Check  your email for  confirmation!"}
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Registration failed: {str(e)}")

@router.post("/register/manager", status_code=status.HTTP_201_CREATED)
async def register_manager(
    user_data: CreateManager, 
    session: AsyncSessionDep
    ) -> dict:

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            data = {
                "email": user_data.email,
                "phone": user_data.phone
            }
            resp = await client.post(f"{BASE_API_URL}/verify-data", json=data)
    except httpx.ConnectError:
        #logger.error("Auth service unreachable")
        return JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)
    except httpx.TimeoutException:
        #logger.error("Auth service timeout")
        return JSONResponse({"detail": "Authentication timeout"}, status_code=504)


    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail"))

    hashed_pass = auth.hash_password(user_data.password)

    try:
        user = Users(
            email=user_data.email.lower(),
            password_hash=hashed_pass,
            phone=user_data.phone,
            role="manager"
        )

        session.add(user)
        await session.flush()

        manager = Manager(id=user.id)
        session.add(manager)
        await session.flush()

        stmt = select(Organization).where(Organization.name == user_data.organization.name)
        org = await session.exec(stmt)
        org = org.first()

        if org:
            raise HTTPException(status_code=409, detail="Organization name already exist")
  
        organization = Organization(
            manager_id = manager.id,
            name = user_data.organization.name,
            address = user_data.organization.address,
            website = user_data.organization.website,
            status="active"
        )
        
        session.add(organization)
        await session.flush()

        manager.organization_id = organization.id
        session.add(manager)

        # Rotar nonce
        user.password_reset_nonce = secrets.token_urlsafe(16)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        metadata = {
            "email": user.email,
            "purpose": "email_verification",
            "nonce": user.password_reset_nonce
        }
            
        token = auth.encode_token(str(user.id), metadata, expires_in=timedelta(hours=24)) 
        confirmation_url = f"{BASE_URL}/auth/verify-email/?token={token['access_token']}"
        html_content = get_confirmation_email_template(confirmation_url)

        await send_email(
            user.email,
            "Confirm Your Api360 Account",
            html_content,
            confirmation_url
        )

        return{"message": "User registred succefull. Check  your email for  confirmation!"}
    except HTTPException as e:
        await session.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Registration failed: {str(e)}")

@router.post("/verify-data", status_code=200)
async def verify_data(
    user_data: UserData, 
    session: AsyncSessionDep
    ) -> dict:

    try: 
        await auth.verify_if_exist(session, user_data.email, user_data.phone)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    
    return {"message": "Ok"}
    
@router.post("/sign-in")
async def sign_in(
    user_data: EmailPasswordRequestForm, 
    session: AsyncSessionDep, 
    response: Response
    ) -> dict:

    try:
        # Cargar user con sus relaciones
        user = await auth.get_user_by_email(session, email=user_data.email)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    if not await auth.verify_password(session, user_data.password, user.password_hash, user.id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    if not user.email_verified_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not verified")

    # Construir metadata
    metadata = {
        "email": user.email,
        "phone": user.phone,
        "role": user.role
    }
    # Agregar campos específicos del rol
    if user.manager and user.role == "manager":
        metadata["organization_id"] = str(user.manager.organization_id) if user.manager.organization_id else None
    elif user.crew and user.role == "crew":
        metadata["airline"] = user.crew.airline

    access_token_data = auth.encode_token(str(user.id), metadata)
    raw, token_hash, exp = auth.gen_refresh_token()

    await auth.save_refresh_in_db(session, user.id, token_hash, exp)

    utils.set_cookies(response, {
        "refresh_token": raw,
        "expires_at": exp
    })

    metadata.update({"id": user.id})

    return {
        "data": {
            "session": {
                "access_token": access_token_data["access_token"],
                "expires_at": access_token_data["exp"],   # Ya debería ser int (timestamp)
                "type": "Bearer"
            },
            "user_data": metadata
        }
    }
    
@router.post("/sign-out", status_code=200)
async def sign_out(
    session: AsyncSessionDep, 
    user_id: str = Header(alias="x-user-id")
    ):

    await auth.revoke_all_user_refresh(session, user_id)
    jsonr = JSONResponse({"message": "All cookies revoked"}, status_code=200)
    return jsonr

@router.post("/refresh")
async def refresh_token(
    session: AsyncSessionDep,
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias="refresh_token")
    ) -> dict:

    if not refresh_token:                          # Si no viene cookie → 401
        raise HTTPException(status_code=401, detail="Missing refresh token")

    rec = await auth.get_refresh_by_hash(session, refresh_token)   # Busca el registro por hash en BD

    print("TOKEN DATA: ", rec)

    if not rec:                                            # Si no existe → token inválido
        raise HTTPException(status_code=401, detail="Invalid refresh")

    if rec.revoked:                                        # Si ya estaba revocado → posible re-uso
        await auth.revoke_all_user_refresh(session, rec.user_id)      # Mitigación: revoca todos
        raise HTTPException(status_code=401, detail="Reused refresh detected")
    
    if rec.expires_at <= utils.now_utc(): 
        print("TOKEN ID:", rec.id)                       # Si expiró → revoca y 401
        await auth.revoke_refresh(session, rec.id)
        raise HTTPException(status_code=401, detail="Expired refresh")

    # ROTACIÓN: invalidamos el refresh usado
    await auth.revoke_refresh(session, rec.id)

    # Creamos un nuevo refresh opaco para el mismo usuario
    new_raw, new_h, new_exp = auth.gen_refresh_token()
    await auth.save_refresh_in_db(session, user_id=rec.user_id, token_hash=new_h, exp=new_exp)

    # Emitimos un nuevo access para ese user
    user = await auth.get_current_user(session, rec.user_id) 

    metadata = {
        "email": user.email,
        "phone": user.phone,
        "role": user.role
    }

    # Agregar campos específicos del rol
    if user.manager and user.role == "manager":
        metadata["organization_id"] = str(user.manager.organization_id) if user.manager.organization_id else None
    elif user.crew and user.role == "crew":
        metadata["airline"] = user.crew.airline           

    # Tu función para cargar el usuario
    access_token = auth.encode_token(sub=str(user.id), metadata=metadata)
    access_token.update({"token_type": "bearer"})

    metadata.update({"id": user.id})

    resp = {"data":{ 
                "session": access_token,
                "user_data": metadata 
                }}
    
    utils.set_cookies(response,
                        {
                            "refresh_token": new_raw, 
                            "expires_at": new_exp
                        }
    )
    return resp

@router.put("/change-password")
async def change_password(
    data: PasswordUpdate, 
    session: AsyncSessionDep, 
    user_id: str = Header(alias="x-user-id")
    ) -> dict:

    if data.current_password == data.new_password:
        raise HTTPException(status_code=400, detail="The new password must be different from your current password.")
    
    try:
        user = await auth.get_current_user(session, user_id)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    
    if not await auth.verify_password(session, data.current_password, user.password_hash, user_id):
        raise HTTPException(status_code=401, detail="Incorrect current password")
    
    if await auth.verify_password(session, data.new_password, user.password_hash, user_id):
        raise HTTPException(status_code=409, detail="The new password must be different from your current password.")

    user.password_hash = auth.hash_password(data.new_password)
    session.add(user)
    await session.commit()

    # Revocar todos los refresh tokens
    await auth.revoke_all_user_refresh(session, user_id)

    return JSONResponse({"message":"Password reset successful. Please sign in again with your new password."}, status_code=status.HTTP_200_OK)
    
@router.get("/verify-email")
async def verify_email(
    token: str, 
    session: AsyncSessionDep
    ) -> dict: 
    
    """Verifica el email del usuario con el token enviado por correo"""
    try:
        # Decodificar directamente el token del query param
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])

        meta = payload.get("metadata")
        print(meta)
        
        # Verificar que sea un token de verificación
        if meta.get("purpose") != "email_verification":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification token"
            )
        
        user = await auth.get_current_user(session, payload.get("sub"))       
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
                
        # Validar nonce
        if not user.password_reset_nonce or user.password_reset_nonce != meta.get("nonce"):
            raise HTTPException(status_code=400, detail="Token already used or invalid")
            

        if user.email_verified_at:
            raise HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Email already verified")
        
        # Marcar email como verificado y invalidar nonce
        user.email_verified_at = utils.now_utc()
        user.password_reset_nonce = None
        session.add(user)
        await session.commit()

        resp = JSONResponse(content="Email verified successfully", status_code=status.HTTP_200_OK)
        return resp
    except JWTError as e:  # ✅ Ahora JWTError está importado
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or expired token: {str(e)}"
        )

@router.post("/forgot-password")
async def forgot_password(
    email: EmailStr, 
    session: AsyncSessionDep
    ) -> dict:

    resp = JSONResponse(content="If the email exists, you will receive a password reset link",
                        status_code=status.HTTP_200_OK)
    try:
        user = await auth.get_user_by_email(session, email=email)
    except Exception as e:
        return str(e)
    
    if not user or user.email_verified_at is None:
        raise HTTPException(status_code=200, detail="If the email exists, you will receive a password reset link")

    # Rotar nonce
    user.password_reset_nonce = secrets.token_urlsafe(16)
    session.add(user)
    await session.commit()
    await session.refresh(user)

    metadata = {
        "email": user.email,
        "purpose": "password_reset",
        "nonce": user.password_reset_nonce
    }
    token = auth.encode_token(sub=str(user.id), metadata=metadata, expires_in=timedelta(minutes=30))

    reset_url = f"http://localhost:3000/reset-password/?token={token['access_token']}"
    html_content = get_password_reset_email_template(reset_url)
    await send_email(user.email, "Reset Your Password - Api360", html_content, reset_url)
    return resp

@router.post("/reset-password")
async def reset_password(
    session: AsyncSessionDep, 
    response: Response, 
    token: str, 
    password: NewPassword
    ) -> dict:

    new_password = password.new_password

    try:
        payload = auth.decode_token(token)
    except ValueError as e:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
    
    meta = payload.get("metadata") or {}
    if meta.get("purpose") != "password_reset":
        raise HTTPException(status_code=400, detail="Invalid reset token")

    user = await session.get(Users, payload["sub"])
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validar nonce
    if not user.password_reset_nonce or user.password_reset_nonce != meta.get("nonce"):
        raise HTTPException(status_code=400, detail="Token already used or invalid")

    # Validar contraseña
    try:
        utils.validate_password(new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    if await auth.verify_password(session, new_password, user.password_hash, user.id):
        raise HTTPException(status_code=409, detail="The new password must be different from your current password.")
    
    user.password_hash = auth.hash_password(new_password)
    user.updated_at = utils.now_utc()

    await auth.revoke_all_user_refresh(session, user.id)

    # Invalidar el token (rotar nonce)
    user.password_reset_nonce = None
    session.add(user)
    await session.commit()
    
    utils.delete_cookies(response, ["refresh_token", "expires_at"])

    return {"message": "Password updated. Sign in again."}

@router.get("/verify-token")
async def verify_token(
    request: Request
    ) -> dict:

    try:
        payload = auth.verify_token(request)
        payload.update({"valid": True})
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    
    jsonr = JSONResponse(payload, status_code=200)
    return jsonr