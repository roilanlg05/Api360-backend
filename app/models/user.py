from pydantic import BaseModel, EmailStr, Field, field_validator
from app.services.auth import ValidatorServices
import enum

validator = ValidatorServices()

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    CREW_MEMBER = "crew_member"


class CreateUser(BaseModel):
    email: EmailStr
    password: str 
    phone: str
    role: UserRole = Field(default=UserRole.CREW_MEMBER)



    @field_validator("password")
    def check_password_strength(cls, v):
        # Llamamos la función del servicio
        return validator.validate_password(v)
    
    @field_validator("phone")
    def validate_phone(cls, v):
        return validator.validate_us_phone(v)
    
class UpdateUser(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    phone: str| None = None



class UserResponse(BaseModel):
    id: str
    email: EmailStr
    phone: str
    role: UserRole

class UserSignIn(BaseModel):
    email: EmailStr
    password: str
