from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Request
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Annotated
from jose import JWTError, jwt
from app.models.user import CreateUser, PasswordUpdate
from app.models.auth_model import EmailPasswordRequestForm
from app.services.helpers import Helpers, AuthHelpers
from app.core.config import Settings
from app.core.db_session import SessionDep
from app.schemas.schemas import Users, Manager, Crew, Driver, RefreshToken
from app.services.smtp import get_confirmation_email_template, get_password_reset_email_template, send_email
from datetime import datetime, timezone, timedelta
from sqlmodel import select

helpers = Helpers()
auth = AuthHelpers()
settings = Settings()

router = APIRouter(prefix="/v1/auth", tags=["Auth"])

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def registre_user(user_raw: CreateUser, db: SessionDep) -> dict:

    hashed_pass = auth.hash_password(user_raw.password)

    try:
        user = Users(
            email=user_raw.email,
            password_hash=hashed_pass,
            phone=user_raw.phone,
            role=user_raw.role
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        match user_raw.role:
            case "admin":
                manager = Manager(id=user.id)
                db.add(manager)
                db.commit()
            case "crew":
                crew = Crew(id=user.id)
                db.add(crew)
                db.commit()
            case _:
                db.rollback()
                raise ValueError("User role not valid")
            
        metadata = {
            "email": user.email,
            "purpose" : "email_verification"
        }
            
        token = auth.encode_token(str(user.id), metadata, expires_in=timedelta(hours=24))
        
        confirmation_url = f"https://www.optionstriker.com/#token={token['access_token']}"
        html_content = get_confirmation_email_template(confirmation_url)

        await send_email(
            user.email,
            "Confirm Your Api360 Account",
            html_content,
            confirmation_url
        )
    
        return {"message": "User registered successfully. Check your email."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Registration failed: {e}")

    
@router.post("/sign-in")
async def sign_in(user_data: Annotated[EmailPasswordRequestForm, Depends()], db: SessionDep, response: Response):
    try:
        # Cargar user con sus relaciones
        user = auth.get_user(db, email=user_data.email)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    if not auth.verify_password(user_data.password, user.password_hash, db, user.id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    if not user.email_verified_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not verified")

    # Construir metadata
    metadata = {
        "id": str(user.id),
        "full_name": user.full_name,
        "email": user.email,
        "profile_pic": user.profile_pic,
        "phone": user.phone,
        "email_verified_at": user.email_verified_at.isoformat() if user.email_verified_at else None,  # ✅ FIX
        "role": user.role
    }

    # Agregar campos específicos del rol
    if user.manager and user.role == "admin":
        metadata["organization_id"] = str(user.manager.organization_id) if user.manager.organization_id else None
    elif user.crew and user.role == "crew":
        metadata["aeroline"] = user.crew.aeroline

    access_token_data = auth.encode_token(str(user.id), metadata)
    raw, token_hash, exp = auth.gen_refresh_token()

    auth.save_refresh_in_db(db, user.id, token_hash, exp)
    helpers.set_cookies(response, {
        "refresh_token": raw,
        "expires_at": exp
    })

    return {
        "data": {
            "session": {
                "access_token": access_token_data["access_token"],
                "issued_at": access_token_data["iat"],  # Ya debería ser int (timestamp)
                "expires_at": access_token_data["exp"],   # Ya debería ser int (timestamp)
                "refresh_token": raw,
                "rf_expires_at": exp.isoformat()
            },
            "user_data": metadata
        }
    }
    


@router.post("/refresh")
async def refresh_token(
    db: SessionDep,
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias="refresh_token") # Lee cookie 'refresh_token'
):
    if not refresh_token:                          # Si no viene cookie → 401
        raise HTTPException(status_code=401, detail="Missing refresh token")

    rec = auth.get_refresh_by_hash(db, refresh_token)                   # Busca el registro por hash en BD

    if not rec:                                            # Si no existe → token inválido
        raise HTTPException(status_code=401, detail="Invalid refresh")

    if rec.revoked:                                        # Si ya estaba revocado → posible re-uso
        auth.revoke_all_user_refresh(db, rec.user_id)      # Mitigación: revoca todos
        raise HTTPException(status_code=401, detail="Reused refresh detected")
    
    if rec.expires_at <= helpers.now_utc():                        # Si expiró → revoca y 401
        auth.revoke_refresh(db, rec.id)
        raise HTTPException(status_code=401, detail="Expired refresh")

    # ROTACIÓN: invalidamos el refresh usado
    auth.revoke_refresh(db, rec.id)

    # Creamos un nuevo refresh opaco para el mismo usuario
    new_raw, new_h, new_exp = auth.gen_refresh_token()
    auth.save_refresh_in_db(db, user_id=rec.user_id, token_hash=new_h, exp=new_exp)

    # Emitimos un nuevo access para ese user
    user = auth.get_user(db, id=rec.user_id)  
    metadata = {
        "id": str(user.id),
        "full_name": user.full_name,
        "email": user.email,
        "profile_pic": user.profile_pic,
        "phone": user.phone,
        "email_verified_at": user.email_verified_at.isoformat() if user.email_verified_at else None,  # ✅ FIX
        "role": user.role
    }

    # Agregar campos específicos del rol
    if user.manager and user.role == "admin":
        metadata["organization_id"] = str(user.manager.organization_id) if user.manager.organization_id else None
    elif user.crew and user.role == "crew":
        metadata["aeroline"] = user.crew.aeroline           

    # Tu función para cargar el usuario
    access_token = auth.encode_token(sub=str(user.id), metadata=metadata)
    resp = {"access_token": access_token, "token_type": "bearer"}
    helpers.set_cookies(response,
                        {
                            "refresh_token": new_raw, 
                            "expires_at": new_exp
                        }
    )
    return resp

@router.post("/sign-out")
async def sign_out(response: Response):
    cookie_list = ["refresh_token", "rf_expires_at"]
    helpers.delete_cookies(response, cookie_list)
    return {"message": "Signed out successfully"}

@router.put("/change-password")
async def change_password(
    passwords: PasswordUpdate,
    db: SessionDep,
    request: Request,
    response: Response,  # ✅ Agregar response para borrar cookies
):
    
    user_data = request.state.user
    """if user.email != user_data["email"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authorized"
        )"""
    
    if passwords.old_password == passwords.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password should be difrent fom your old password"
        )

    if not passwords.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password is required"
        )

    try:
        helpers.validate_password(passwords.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        )

    db_user = db.exec(select(Users).where(Users.email == user_data["email"])).one()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # ✅ Actualizar contraseña
    db_user.password_hash = auth.hash_password(passwords.new_password)
    db_user.updated_at = helpers.now_utc()
    db.add(db_user)
    db.commit()

    # ✅ IMPORTANTE: Revocar todos los refresh tokens del usuario
    auth.revoke_all_user_refresh(db, db_user.id)

    # ✅ Borrar cookie del refresh_token actual
    helpers.delete_cookies(response, ["refresh_token", "expires_at"])

    return {
        "message": "Password reset successful. Please sign in again with your new password."
    }
    
@router.get("/verify-email")
async def verify_email(token: str, db: SessionDep):  # ✅ token como query parameter
    """Verifica el email del usuario con el token enviado por correo"""
    try:
        # ✅ Decodificar directamente el token del query param (no del header)
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])

        print(payload)
        
        # Verificar que sea un token de verificación
        if payload.get("metadata").get("purpose") != "email_verification":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification token"
            )
        
        user_id = payload.get("sub")
        user = db.get(Users, user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.email_verified_at:
            return {"message": "Email already verified"}
        
        # Marcar email como verificado
        user.email_verified_at = helpers.now_utc()
        db.add(user)
        db.commit()
        
        return {"message": "Email verified successfully"}
        
    except JWTError as e:  # ✅ Ahora JWTError está importado
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or expired token: {str(e)}"
        )

@router.post("/forgot-password")
async def forgot_password(email: str, db: SessionDep):
    """Envía email con link para resetear contraseña"""
    try:
        user = auth.get_user(db, email=email)
    except Exception:
        # ✅ No revelar si el email existe (seguridad)
        return {"message": "If the email exists, you will receive a password reset link"}
    
    # ✅ Generar token de reset con expiración de 1 hora
    metadata = {
        "email": user.email,
        "purpose": "password_reset"
    }
    
    token = auth.encode_token(
        sub=str(user.id),
        metadata=metadata,
        expires_in=timedelta(hours=1)  # ✅ Más corto que verificación de email
    )
    
    # ✅ URL para resetear contraseña
    reset_url = f"https://www.optionstriker.com/reset-password?token={token['access_token']}"
    html_content = get_password_reset_email_template(reset_url)
    
    await send_email(
        user.email,
        "Reset Your Password - Api360",
        html_content,
        reset_url
    )
    
    return {"message": "If the email exists, you will receive a password reset link"}


@router.post("/reset-password")
async def reset_password(
    token: str,
    new_password: str,
    db: SessionDep,
    response: Response
):
    """Resetea la contraseña usando el token del email"""
    try:
        # ✅ Decodificar token
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        
        # ✅ Verificar que sea token de reset
        if payload.get("purpose") != "password_reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset token"
            )
        
        # ✅ Validar nueva contraseña
        try:
            helpers.validate_password(new_password)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc)
            )
        
        # ✅ Obtener usuario
        user_id = payload.get("sub")
        user = db.get(Users, user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # ✅ Actualizar contraseña
        user.password_hash = auth.hash_password(new_password)
        user.updated_at = datetime.now(timezone.utc)
        db.add(user)
        db.commit()
        
        # ✅ CRÍTICO: Revocar todos los refresh tokens
        auth.revoke_all_user_refresh(db, user.id)
        
        # ✅ Borrar cookies si existen
        helpers.delete_cookies(response, ["refresh_token", "expires_at"])
        
        return {
            "message": "Password reset successful. Please sign in with your new password."
        }
        
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or expired token: {str(e)}"
        )
