from pydantic import BaseModel, EmailStr, Field, field_validator
from app.models.user import UserRole
from app.services.utils import Utils

utils = Utils()

class CreateDriver(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    phone: str | None = None
    role: str = UserRole.DRIVER

    @field_validator("password")
    def check_password_strength(cls, v):
        return utils.validate_password(v)
    
    @field_validator("phone")
    def validate_phone(cls, v):
        if v is not None:
            return utils.validate_us_phone(v)
        
    
class DriverResponse(BaseModel):
    id: str
    full_name: str
    email: str
    phone: str
    role: str
    location_id: str