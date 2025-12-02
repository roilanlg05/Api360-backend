from fastapi import Response, Request, HTTPException, status
from shared.schemas.schemas import Users, Token
from datetime import datetime, timedelta, timezone
from argon2.exceptions import VerifyMismatchError
from shared.database.db_settings import AsyncSessionDep
from sqlalchemy.orm import selectinload
from config.settings import Settings
from argon2 import PasswordHasher
from jose import jwt, JWTError
from sqlmodel import select
import hashlib
import secrets
import uuid
import re


settings = Settings()

ph = PasswordHasher()  # usa parámetros seguros por defecto

class Utils:

    @staticmethod
    def validate_password(v: str) -> str:
        # Mínimo 8 caracteres
        if len(v) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        # Al menos una mayúscula
        if not any(c.isupper() for c in v):
            raise ValueError("Debe incluir al menos una letra mayúscula")
        # Al menos una minúscula
        if not any(c.islower() for c in v):
            raise ValueError("Debe incluir al menos una letra minúscula")
        # Al menos un número
        if not any(c.isdigit() for c in v):
            raise ValueError("Debe incluir al menos un número")
        # Al menos un símbolo especial
        special_chars = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"
        if not any(c in special_chars for c in v):
            raise ValueError("Debe incluir al menos un símbolo especial")

        return v

    @staticmethod
    def validate_us_phone(v: str) -> str:
        """
        Valida y normaliza un número de teléfono de EE.UU. al formato +1XXXXXXXXXX.
        """
        # Patrón de validación para números de EE.UU.
        pattern = re.compile(
            r"^(?:\+1\s?)?\(?([2-9][0-9]{2})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$"
        )

        if not pattern.match(v):
            raise ValueError("Número de teléfono inválido. Ejemplos válidos: +1 (555) 123-4567, 555-123-4567, 5551234567",
            )

        # Normalización al formato E.164
        digits = re.sub(r"\D", "", v)
        if len(digits) == 10:
            digits = "1" + digits
        normalized = f"+{digits}"

        return normalized

    @staticmethod
    def set_cookies(response: Response, data:dict):
        for k, v in data.items():
            response.set_cookie(
                key=k,
                value=v, 
                httponly=True, 
                secure=False,  
                samesite="lax",
                domain="192.168.0.133",
                path="/",
                max_age=30 * 24 * 60 * 60,  # 30 días
                )

    @staticmethod
    def delete_cookies(response: Response, cookies:list):
        for cookie in cookies:
            response.delete_cookie(
                key=cookie, 
                path="/",
                httponly=True,
                secure=False,        # Descomentar con HTTPS
                samesite="lax",
                domain="192.168.0.133",
            )

    @staticmethod
    def now_utc():                                    # Pequeña utilidad para “ahora” en UTC
        return datetime.now(timezone.utc)


class Auth:

    @staticmethod
    async def get_current_user(session: AsyncSessionDep, id: str) -> Users:
        stmt = select(Users).options(
            selectinload(Users.manager),
            selectinload(Users.crew)
        ).where(Users.id == id)
        
        result = await session.exec(stmt)
        user = result.first()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        return user

    @staticmethod
    def hash_password(plain: str) -> str:
        return ph.hash(plain + settings.PEPPER)

    @staticmethod
    async def verify_password(session: AsyncSessionDep, plain: str, hashed: str,  user_id: str | None = None) -> bool:
        try:
            # 1. Verificar contraseña
            ph.verify(hashed, plain + settings.PEPPER)
            
            # 2. Si es válida, revisar si necesita rehash
            if ph.check_needs_rehash(hashed):
                new_hash = ph.hash(plain + settings.PEPPER)
                # 3. Actualizar en BD (necesitas sesión y user_id)
                if session and user_id:
                    user = await session.get(Users, user_id)
                    user.password_hash = new_hash
                    await session.commit()
                return True  # Contraseña correcta
            
            return True  # Contraseña correcta y hash actualizado
            
        except VerifyMismatchError:
            return False  # Contraseña incorrecta

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
    def encode_token(
        sub: str, 
        metadata: dict | None = None,
        expires_in: timedelta = timedelta(minutes=int(settings.TOKEN_DURATION))  # ✅ Parámetro con default
        ) -> dict:
        
        now = datetime.now(timezone.utc)
        iat = int(now.timestamp())
        exp = int((now + expires_in).timestamp())

        payload = {
            "sub": sub,
            "iat": iat,
            "exp": exp
        }

        if metadata:
            payload["metadata"] = metadata

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
        
        return {
            "access_token": token,
            #"iat": iat,
            "exp": exp
        }
    
    @staticmethod
    def decode_token(token):
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
            return payload 
        except JWTError:
            raise ValueError("Invalid token")
    
    @staticmethod
    def verify_token(request: Request) -> dict:
        token = Auth.get_token(request)
        payload = Auth.decode_token(token)
        return payload
        
    @staticmethod
    def gen_refresh_token() -> tuple[str, str, datetime]:
        """Genera un refresh token aleatorio"""
        raw = secrets.token_urlsafe(64)
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        exp = datetime.now(timezone.utc) + timedelta(days=30)
        
        return raw, token_hash, exp  # ✅ Retorna valores reales
    
    @staticmethod
    async def get_refresh_by_hash(session: AsyncSessionDep, refresh_token: str) -> Token | None:

        refresh_token = hashlib.sha256(refresh_token.encode()).hexdigest()  # Calcula hash del valor recibido

        # Busca por hash y devuelve el primero
        stmt = select(Token).where(Token.token_hash == refresh_token)
        token = await session.exec(stmt)          
        token = token.first()
        return token
    
    @staticmethod
    async def save_refresh_in_db(session: AsyncSessionDep, user_id: uuid.UUID, token_hash: str, exp: datetime) -> Token:
        """Guarda un refresh token en la base de datos"""
        refresh_token = Token(
            user_id=user_id,
            token_hash=token_hash,  # ✅ Usa el valor, no el string "token_hash"
            expires_at=exp,         # ✅ Usa el valor, no el string "expires_at"
            revoked=False,
            token_type="refresh"
        )
        session.add(refresh_token)
        await session.commit()
        await session.refresh(refresh_token)
        return refresh_token
    
    @staticmethod
    async def revoke_refresh(session:AsyncSessionDep, refresh_id: int):
        rec = await session.get(Token, refresh_id)  # Busca por PK
        if rec and not rec.revoked:
            rec.revoked = True                       # Marca como revocado
            session.add(rec)
            await session.commit()
            await session.refresh(rec)
        return rec
    
    @staticmethod
    async def revoke_all_user_refresh(session:AsyncSessionDep, user_id: int):
        stmt = select(Token).where(Token.user_id == user_id, Token.revoked == False, Token.token_type=="refresh")
        rows = await session.exec(stmt)
        all_rows= rows.all()
        for r in all_rows:
            r.revoked = True                         # Revoca todos los refresh del usuario
            session.add(r)
        await session.commit()
        return len(all_rows)


    @staticmethod
    def verify_role(roles: list):
        def _dep(request: Request):
            user: dict = request.state.user
            user_data = user.get("metadata")
            role = user_data.get("role")
            if role not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not Authorized: We couldn't validate the role"
                )
            return user
        return _dep
    
    @staticmethod
    async def get_user_by_email(session: AsyncSessionDep, email: str) -> Users:
        query = (
        select(Users)
        .options(
            selectinload(Users.manager),
            selectinload(Users.crew)
        )
        .where(Users.email == email)
    )
        result = await session.exec(query)
        user = result.first()
        return user
    
    @staticmethod
    async def verify_if_exist(session: AsyncSessionDep, email: str, phone: str | None = None):
        from sqlalchemy import or_, func

        conds = [func.lower(Users.email) == email.lower()]
        if phone:
            conds.append(Users.phone == phone)

        stmt = select(Users.email, Users.phone).where(or_(*conds))
        result = await session.exec(stmt)
        row = result.first()

        if not row:
            return

        if row[0] and row[0].lower() == email.lower():
            raise ValueError("Email already in use")
        if phone and row[1] == phone:
            raise ValueError("Phone already in use")


