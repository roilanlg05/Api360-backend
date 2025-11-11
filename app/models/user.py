from pydantic import BaseModel, EmailStr, Field, field_validator
from fastapi import Form
from app.services.helpers import Helpers
import enum
from datetime import datetime



helpers = Helpers()

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    CREW_MEMBER = "crew"
    DRIVER = "driver"



class CreateUser(BaseModel):
    email: EmailStr
    password: str = Form(json_schema_extra={"format": "password"})
    phone: str
    role: UserRole = Field(default=UserRole.CREW_MEMBER)



    @field_validator("password")
    def check_password_strength(cls, v):
        # Llamamos la función del servicio
        return helpers.validate_password(v)
    
    @field_validator("phone")
    def validate_phone(cls, v):
        return helpers.validate_us_phone(v)
    
class UpdateUser(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None = Form(json_schema_extra={"format": "password"})
    phone: str| None = None

class PasswordUpdate(BaseModel):
    old_password: str | None = Form(json_schema_extra={"format": "password"})
    new_password: str | None = Form(json_schema_extra={"format": "password"})


class ManagerResponse(BaseModel):
    id: str
    full_name: str | None = None
    email: EmailStr
    phone: str
    profile_pic: str | None = None
    role: UserRole
    organization_id: str | None = None
    email_verified_at: datetime | None = None

