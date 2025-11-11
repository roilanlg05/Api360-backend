from fastapi import Form
from pydantic import EmailStr, field_validator


class EmailPasswordRequestForm():
    def __init__(
        self,
        email: EmailStr = Form(),
        password: str = Form(json_schema_extra={"format": "password"})
    ):
        self.email = email
        self.password = password
