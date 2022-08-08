from typing import List
from typing import Optional

from pydantic import BaseModel
from pydantic import Field

from .validator_block import ValidatorBlock


class ValidatorConfig(BaseModel):
    type_: str = Field(alias='@type')
    zero_state: ValidatorBlock
    init_block: ValidatorBlock
    hard_fork: Optional[List[ValidatorBlock]]
