from typing import List

from pydantic import BaseModel
from pydantic import Field

from .dht_node import DHTNode


class DHTNodes(BaseModel):
    type_: str = Field(alias='@types')
    nodes: List[DHTNode]
