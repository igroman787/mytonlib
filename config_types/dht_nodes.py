from typing import List, Optional

from pydantic import BaseModel
from pydantic import Field

from .dht_node import DHTNode


class DHTNodes(BaseModel):
    type_: Optional[str] = Field(alias='@type')
    nodes: Optional[List[DHTNode]]
