from typing import List, Optional

from pydantic import BaseModel
from pydantic import Field

from .dht_addr import DHTAddress


class DHTAddressList(BaseModel):
    type_: str = Field(alias='@type')
    address_list: Optional[List[DHTAddress]]
    version: int
    reinit_date: int
    priority: int
    expire_date: Optional[int]
