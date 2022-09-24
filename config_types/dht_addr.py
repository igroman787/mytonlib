from pydantic import BaseModel
from pydantic import Field


class DHTAddress(BaseModel):
    type_: str = Field(alias='@type')
    ip: str
    port: str
