from pydantic import BaseModel, EmailStr, Field, field_validator
from app.services.utils import Utils
import enum
from datetime import datetime



utils = Utils()

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    CREW_MEMBER = "crew"
    DRIVER = "driver"



class CreateUser(BaseModel):
    email: EmailStr
    password: str 
    phone: str | None = None
    aeroline: str | None = None
    role: UserRole = Field(default=UserRole.CREW_MEMBER)



    @field_validator("password")
    def check_password_strength(cls, v):
        # Llamamos la función del servicio
        return utils.validate_password(v)
    
    @field_validator("phone")
    def validate_phone(cls, v):
        if v is not None:
            return utils.validate_us_phone(v)
    
class UpdateUser(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None 
    phone: str| None = None
    
class EmailPasswordRequestForm(BaseModel):
    email: EmailStr
    password: str

class PasswordUpdate(BaseModel):
    old_password: str 
    new_password: str

class UserResponse(BaseModel):
    id: str
    full_name: str | None = None
    email: EmailStr
    phone: str
    profile_pic: str | None = None
    role: UserRole
    organization_id: str | None = None
    aeroline: str | None =None
    email_verified_at: datetime | None = None

