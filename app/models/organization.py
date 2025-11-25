from pydantic import BaseModel

class CreateOrganization(BaseModel):
    manager_id: str
    name: str
    address: str
    website: str | None = None