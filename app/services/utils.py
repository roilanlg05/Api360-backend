from fastapi import Response, Request, HTTPException, status
from jose import jwt, JWTError
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from app.schemas.schemas import Users, RefreshToken
from app.core.config import Settings
from sqlmodel import select
from sqlalchemy.orm import selectinload
import uuid

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
                secure=True, 
                samesite="none", #should be "lax" in prod
                #domain="192.168.0.148",
                path="/",
                max_age=30 * 24 * 60 * 60  # 30 días
                )

    @staticmethod
    def delete_cookies(response: Response, cookies:list):
        for cookie in cookies:
            response.delete_cookie(
                key=cookie, 
                path="/"
                )

    @staticmethod
    def now_utc():                                    # Pequeña utilidad para “ahora” en UTC
        return datetime.now(timezone.utc)


class AuthHelpers:


    @staticmethod
    def get_current_user(db, id) -> Users:
        user = db.get(Users, id)
        return user

    @staticmethod
    def hash_password(plain: str) -> str:
        return ph.hash(plain + settings.PEPPER)

    @staticmethod
    def verify_password(plain: str, hashed: str, db=None, user_id=None) -> bool:
        try:
            # 1. Verificar contraseña
            ph.verify(hashed, plain + settings.PEPPER)
            
            # 2. Si es válida, revisar si necesita rehash
            if ph.check_needs_rehash(hashed):
                new_hash = ph.hash(plain + settings.PEPPER)
                # 3. Actualizar en BD (necesitas sesión y user_id)
                if db and user_id:
                    user = db.get(Users, user_id)
                    user.password_hash = new_hash
                    db.commit()
                    print(f"🔄 Password rehashed for user {user_id}: {new_hash[:20]}...")
                return True  # Contraseña correcta
            
            return True  # Contraseña correcta y hash actualizado
            
        except VerifyMismatchError:
            return False  # Contraseña incorrecta

    @staticmethod
    def get_token(request: Request):
        auth_header = request.headers.get("Authorization")
        print(auth_header)

        if not auth_header or not auth_header.startswith("Bearer "):
            raise ValueError("Missing authentication token")
        
        token = auth_header.split(" ", 1)[1].strip()

        if not token:
            raise HTTPException(status_code=401, detail="Missing authentication token")
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
            "iat": iat,
            "exp": exp
        }
    
    @staticmethod
    def decode_token(request: Request) -> dict:

        token = AuthHelpers.get_token(request)
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
            return payload 
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        

    @staticmethod
    def gen_refresh_token() -> tuple[str, str, datetime]:
        """Genera un refresh token aleatorio"""
        raw = secrets.token_urlsafe(64)
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        exp = datetime.now(timezone.utc) + timedelta(days=30)
        
        return raw, token_hash, exp  # ✅ Retorna valores reales
    
    @staticmethod
    def get_refresh_by_hash(db, refresh_token: str) -> RefreshToken | None:

        refresh_token = hashlib.sha256(refresh_token.encode()).hexdigest()  # Calcula hash del valor recibido

        stmt = select(RefreshToken).where(RefreshToken.token_hash == refresh_token)
        return db.exec(stmt).first()            # Busca por hash y devuelve el primero
    
    @staticmethod
    def save_refresh_in_db(db, user_id: uuid.UUID, token_hash: str, exp: datetime) -> RefreshToken:
        """Guarda un refresh token en la base de datos"""
        refresh_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,  # ✅ Usa el valor, no el string "token_hash"
            expires_at=exp,         # ✅ Usa el valor, no el string "expires_at"
            revoked=False
        )
        db.add(refresh_token)
        db.commit()
        db.refresh(refresh_token)
        return refresh_token
    
    @staticmethod
    def revoke_refresh(db, refresh_id: int):
        rec = db.get(RefreshToken, refresh_id)  # Busca por PK
        if rec and not rec.revoked:
            rec.revoked = True                       # Marca como revocado
            db.add(rec)
            db.commit()
        return rec
    
    @staticmethod
    def revoke_all_user_refresh(db, user_id: int):
        stmt = select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked == False)
        rows = db.exec(stmt).all()
        for r in rows:
            r.revoked = True                         # Revoca todos los refresh del usuario
            db.add(r)
        db.commit()
        return len(rows)


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
    def get_user_by_email(db, email: str) -> Users:
        query = (
        select(Users)
        .options(
            selectinload(Users.manager),
            selectinload(Users.crew)
        )
        .where(Users.email == email)
    )
        user = db.exec(query).first()
        return user
    
    @staticmethod
    def verify_if_exist(db, email: str, phone: str | None):
        from sqlalchemy import or_, func
        conds = [func.lower(Users.email) == email]
        if phone:
            conds.append(Users.phone == phone)

        row = db.exec(
            select(Users.email, Users.phone).where(or_(*conds))
        ).first()

        if not row:
            return

        if row[0] and row[0].lower() == email:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")
        if phone and row[1] == phone:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone already in use")


