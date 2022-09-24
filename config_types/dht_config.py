from typing import Optional
from pydantic import BaseModel
from pydantic import Field

from .dht_nodes import DHTNodes


class DHTConfig(BaseModel):
    type_: str = Field(alias='@type')
    k: int
    a: int
    static_nodes: Optional[DHTNodes]
