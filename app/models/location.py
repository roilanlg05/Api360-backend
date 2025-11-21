from pydantic import BaseModel

class CreateLocation(BaseModel):
    name: str
    point: str