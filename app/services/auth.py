from fastapi import HTTPException, status, Response, Request
from app.core.supabase_config import supabase
import re

class ValidatorServices:
    @staticmethod
    def validate_password(v: str) -> str:
        # Mínimo 8 caracteres
        if len(v) < 8:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña debe tener al menos 8 caracteres")
        # Al menos una mayúscula
        if not any(c.isupper() for c in v):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Debe incluir al menos una letra mayúscula")
        # Al menos una minúscula
        if not any(c.islower() for c in v):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Debe incluir al menos una letra minúscula")
        # Al menos un número
        if not any(c.isdigit() for c in v):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Debe incluir al menos un número")
        # Al menos un símbolo especial
        special_chars = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"
        if not any(c in special_chars for c in v):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Debe incluir al menos un símbolo especial")

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
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Número de teléfono inválido. Ejemplos válidos: +1 (555) 123-4567, 555-123-4567, 5551234567",
            )

        # Normalización al formato E.164
        digits = re.sub(r"\D", "", v)
        if len(digits) == 10:
            digits = "1" + digits
        normalized = f"+{digits}"

        return normalized
    

def set_cookies(response: Response, data:dict):
    for k, v in data.items():
        response.set_cookie(key=k, value=v, httponly=True, samesite="lax", path="/")


def delete_cookies(response: Response, cookies:list):
    for cookie in cookies:
        response.delete_cookie(key=cookie, path="/")
    
def verify_token(request: Request) -> dict:

    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token faltante o inválido")
    
    token = auth_header.split(" ", 1)[1].strip()

    try:
        claims = supabase.auth.get_claims(jwt=token)
        user_metadata = claims.get("claims", {}).get("user_metadata", {})
        role = user_metadata.get("role")

        if not role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Rol no encontrado en el token")
        
        # Devuelve lo que necesites reutilizar en la ruta
        return {"role": role, "email": user_metadata.get("email")}
    
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token inválido o expirado: {e}")

def verify_role(roles: list):

    allowed = {roles} if isinstance(roles, str) else set(roles)
    # Factory: devuelve una función que FastAPI usará como dependencia

    def _dep(request: Request):

        data = verify_token(request)

        if data.get("role") not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")
        return data  # puedes devolver True si solo quieres un booleano
        
    return _dep