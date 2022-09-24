from typing import List, Optional

from pydantic import BaseModel
from pydantic import Field

from .dht_config import DHTConfig
from .liteserver_config import LiteserverConfig
from .validator_config import ValidatorConfig


class GlobalConfig(BaseModel):
    type_: Optional[str] = Field(alias='@type')
    dht: Optional[DHTConfig]
    lite_servers: List[LiteserverConfig] = Field(alias='liteservers')
    validator_config: ValidatorConfig = Field(alias='validator')
