from pydantic import BaseModel


class ValidatorBlock(BaseModel):
    workchain: int
    shard: int
    seqno: int
    root_hash: str
    file_hash: str
