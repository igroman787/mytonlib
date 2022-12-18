import copy
from typing import Optional, Union, Tuple

from adnl import crypto
from adnl import const
from adnl import tl_object


class BaseQuery:
    def __init__(
            self,
            schema_id: str,
            payload: Optional[Union[bytes, 'BaseQuery']]
    ):
        self.schema_id = crypto.crc32(schema_id)
        if payload:
            if isinstance(payload, BaseQuery):
                self.payload = tl_object.TLBytes(payload.build())
            else:
                self.payload = tl_object.TLBytes(payload)

    def build(self):
        raise Exception('Not implemented')

    def check_response(self, resp: bytes, exception=False):
        raise Exception('Not implemented')

    def validate_response(self, resp: bytes):
        raise Exception('Not implemented')


class AdnlMsgQuery(BaseQuery):
    def __init__(self, payload: Union[bytes, BaseQuery]):
        super().__init__(const.SCHEMA_ADNL_QUERY, payload)
        self.query_id = ''

    def build(self) -> bytes:
        self.query_id = crypto.random_bytes(32)
        query = (
                crypto.random_bytes(32) +  # nonce
                self.schema_id +
                self.query_id +
                self.payload.get_bytes()
        )
        # checksum
        query += crypto.sha256(query)
        # size
        query = len(query).to_bytes(4, byteorder='little') + query
        return query

    def check_response(self, resp: bytes, exception=False):
        status = all([
            resp[0:4] == crypto.crc32(const.SCHEMA_ADNL_ANSWER),
            resp[4:36] == self.query_id
        ])
        if exception and not status:
            raise Exception('Invalid query')
        return status


class LiteServerQuery(BaseQuery):
    def __init__(self, payload: Union[bytes, 'BaseQuery']):
        super().__init__(const.SCHEMA_LITE_QUERY, payload)

    def build(self):
        return self.schema_id + self.payload.get_bytes()


def schema_query(schema_id: str) -> AdnlMsgQuery:
    payload = crypto.crc32(schema_id)
    lite_query = LiteServerQuery(payload)
    adnl_query = AdnlMsgQuery(lite_query)
    return adnl_query


class TLPackage:
    def __init__(self, tl_obj: Optional[tl_object.TLMetaObject]):
        self.tl_obj = tl_obj
        self.buffer = b''
        self.query_id = None

    def __add__(self, value):
        self.buffer = b''.join([*self.buffer, value])

    def build(self) -> bytes:
        # nonce
        self + crypto.nonce()
        # adnl schema id
        self + crypto.crc32(const.SCHEMA_ADNL_QUERY)
        # query_id
        self + crypto.nonce()

    def build_ping(self) -> bytes:
        nonce = crypto.nonce()
        schema_id = crypto.crc32(const.SCHEMA_PING)
        self.query_id = crypto.random_bytes(8)
        lite_query = schema_id + self.query_id
        checksum = crypto.sha256(nonce + lite_query)
        sz = len(nonce + lite_query + checksum).to_bytes(4, byteorder="little")
        return sz + nonce + lite_query + checksum

    def masterchain(self):
        ms_schema_id = crypto.crc32(const.SCHEMA_GET_MASTERCHAIN)
        lite_query = LiteServerQuery(ms_schema_id)
        adnl_query = AdnlMsgQuery(lite_query)

        sdata = adnl_query.build()
        self.query_id = adnl_query.query_id
        return sdata



