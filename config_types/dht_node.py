from typing import Optional

from pydantic import BaseModel
from pydantic import Field

from .dht_address_list import DHTAddressList
from .server_id import ServerId


class DHTNode(BaseModel):
    type_: str = Field(alias='@type')
    server_id: Optional[ServerId]
    addr_list: Optional[DHTAddressList]
    version: int
    signature: str
