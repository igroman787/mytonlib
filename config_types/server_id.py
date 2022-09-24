from pydantic import BaseModel
from pydantic import Field


class ServerId(BaseModel):
    type_: str = Field(alias='@type')
    key: str
