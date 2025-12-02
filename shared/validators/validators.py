import re


class Validators:
    
    @staticmethod
    def validate_password(v: str) -> str:
        # Mínimo 8 caracteres
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        # Al menos una mayúscula
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        # Al menos una minúscula
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        # Al menos un número
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        # Al menos un símbolo especial (incluye guion explícitamente)
        special_chars = set("!@#$%^&*()_=+[]{};:,.<>?/\\|~`'\"-")
        if not any(c in special_chars for c in v):
            raise ValueError("Password must contain at least one special character")

        return v

    @staticmethod
    def validate_us_phone(v: str) -> str:
        """
        Valida y normaliza un número de teléfono de EE.UU. al formato +1XXXXXXXXXX.
        """
        pattern = re.compile(
            r"^(?:\+1\s?)?\(?([2-9][0-9]{2})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$"
        )

        if not pattern.match(v):
            raise ValueError(
                "Invalid phone number. Examples: +1 (555) 123-4567, 555-123-4567, 5551234567"
            )

        # Normalización al formato E.164
        digits = re.sub(r"\D", "", v)
        if len(digits) == 10:
            digits = "1" + digits
        normalized = f"+{digits}"

        return normalized


# Instancia global para usar en los modelos
validators = Validators()