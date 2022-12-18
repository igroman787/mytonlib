from .tl_object import *
from adnl import const
from adnl import crypto


# [tonNode.blockId]
# workchain:int
# shard:long
# seqno:int
class BlockId(TLMetaObject):
    workchain = TLInt()
    shard = TLLong()
    seqno = TLInt()
    root_hash = TLInt256()
    file_hash = TLInt256()


# [tonNode.blockIdExt]
# workchain:int
# shard:long
# seqno:int
# root_hash:int256
# file_hash:int256
class BlockExtId(TLMetaObject):
    workchain = TLInt()
    shard = TLLong()
    seqno = TLInt()
    root_hash = TLInt256()
    file_hash = TLInt256()


# [tonNode.zeroStateIdExt]
# workchain:int
# root_hash:int256
# file_hash:int256
class ZeroStateIdExt(TLMetaObject):
    workchain = TLInt()
    root_hash = TLInt256()
    file_hash = TLInt256()


# [liteServer.masterchainInfo]
# last:tonNode.blockIdExt
# state_root_hash:int256
# init:tonNode.zeroStateIdExt
class MasterchainInfo(TLMetaObject):
    last = BlockExtId()
    state_root_hash = TLInt256()
    init = ZeroStateIdExt()

    def validate_response(self, data: bytes) -> bool:
        ms_res_id = crypto.crc32(const.SCHEMA_GET_MASTERCHAIN_RES)
        resp_schema_id = self.response_schema_id(data)
        return ms_res_id == resp_schema_id
