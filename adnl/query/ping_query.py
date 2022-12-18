from adnl import crypto
from adnl import const
from .adnl_query import BaseQuery


class PingQuery(BaseQuery):
    def __init__(self):
        super().__init__(const.SCHEMA_PING, payload=None)
        self.query_id = None

    def build(self) -> bytes:
        nonce = crypto.nonce()
        schema_id = crypto.crc32(const.SCHEMA_PING)
        self.query_id = crypto.random_bytes(8)
        query = schema_id + self.query_id
        checksum = crypto.sha256(nonce + query)
        sz = len(nonce + query + checksum).to_bytes(4, byteorder="little")
        return sz + nonce + query + checksum

    def validate_response(self, resp: bytes):
        scheme_rid = crypto.crc32("tcp.pong random_id:long = tcp.Pong")
        if resp[0:4] != scheme_rid:
            raise Exception("Scheme mismatch")
        if resp[4:] != self.query_id:
            raise Exception("Query id mismatch")
