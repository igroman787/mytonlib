from typing import Union
from typing import Optional

from adnl import const
from adnl import crypto
from .base_query import BaseQuery


class AdnlQuery(BaseQuery):
    def __init__(
            self,
            schema_id: str,
            payload: Optional[Union[bytes, 'BaseQuery']] = None,
            size_query_id: Optional[int] = 32
    ):
        super().__init__(schema_id, payload)
        self.query_id = ''
        self.payload = payload
        self.size_query_id = size_query_id

    def build(self) -> bytes:
        self.query_id = crypto.random_bytes(self.size_query_id)
        query = (
                crypto.random_bytes(32) +  # nonce
                self.schema_id +
                self.query_id
        )
        if self.payload:
            query += self.payload
        # checksum
        query += crypto.sha256(query)
        # size
        query = len(query).to_bytes(4, byteorder='little') + query
        return query

"""
        nonce = crypto.nonce()
        schema_id = crypto.crc32(const.SCHEMA_PING)
        query_id = crypto.random_bytes(8)
        lite_query = schema_id + self.query_id
        checksum = crypto.sha256(nonce + lite_query)
        sz = len(nonce + lite_query + checksum).to_bytes(4, byteorder="little")
        return sz + nonce + lite_query + checksum
"""