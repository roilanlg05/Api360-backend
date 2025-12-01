import re

class Validators:
    """Funciones de validación compartidas para modelos Pydantic"""
    
    @staticmethod
    def validate_password(password: str) -> str:
        """
        Valida que la contraseña cumpla con los requisitos de seguridad:
        - Mínimo 8 caracteres
        - Al menos una mayúscula
        - Al menos una minúscula
        - Al menos un número
        - Al menos un carácter especial
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValueError("Password must contain at least one special character")
        return password

    @staticmethod
    def validate_us_phone(phone: str) -> str:
        """
        Valida y formatea números de teléfono de EE.UU.
        Acepta formatos: +1XXXXXXXXXX, 1XXXXXXXXXX, XXXXXXXXXX
        Retorna formato: +1XXXXXXXXXX
        """
        # Elimina espacios, guiones y paréntesis
        cleaned = re.sub(r"[\s\-\(\)]", "", phone)
        
        # Elimina el prefijo +1 o 1 si existe
        if cleaned.startswith("+1"):
            cleaned = cleaned[2:]
        elif cleaned.startswith("1") and len(cleaned) == 11:
            cleaned = cleaned[1:]
        
        # Valida que sean 10 dígitos
        if not re.match(r"^\d{10}$", cleaned):
            raise ValueError("Invalid US phone number. Must be 10 digits.")
        
        return f"+1{cleaned}"


# Instancia global para uso en modelos
validators = Validators()