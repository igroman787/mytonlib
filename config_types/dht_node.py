from pydantic import BaseModel
from pydantic import Field

from .dht_address_list import DHTAddressList
from .server_id import ServerId


class DHTNode(BaseModel):
    type_: str = Field(alias='@types')
    server_id: ServerId
    addr_list: DHTAddressList
    version: int
    signature: str
