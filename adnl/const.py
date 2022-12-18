BOC_HEADER = 'b5ee9c72'
ID_LITE_QUERY = 0xdf068c79
ID_ADNL_QUERY = 0x7af98bb4
ID_GET_MASTERCHAIN_INFO = 0x2ee6b589

BYTES_BIG_SIGN = 0xFE
BYTES_PADDING = 0x00

ONE_BYTE_LIMIT = 256

SCHEMA_ADNL_QUERY = (
    'adnl.message.query query_id:int256 query:bytes = adnl.Message'
)
SCHEMA_ADNL_ANSWER = (
    'adnl.message.answer query_id:int256 answer:bytes = adnl.Message'
)
SCHEMA_PING = 'tcp.ping random_id:long = tcp.Pong'
SCHEMA_PONG = 'tcp.pong random_id:long = tcp.Pong'
SCHEMA_LITE_QUERY = 'liteServer.query data:bytes = Object'
SCHEMA_GET_MASTERCHAIN = (
    'liteServer.getMasterchainInfo = liteServer.MasterchainInfo'
)
SCHEMA_GET_MASTERCHAIN_RES = (
    "liteServer.masterchainInfo last:tonNode.blockIdExt "
    "state_root_hash:int256 init:tonNode.zeroStateIdExt = "
    "liteServer.MasterchainInfo"
)

SCHEMA_RUN_SMC_METHOD = (
    "liteServer.runSmcMethod mode:# id:tonNode.blockIdExt account:liteServer"
    ".accountId method_id:long params:bytes = liteServer.RunMethodResult"
)

SCHEMA_RUN_SMC_METHOD_RESULT = (
    "liteServer.runMethodResult mode:# id:tonNode.blockIdExt shardblk:tonNode"
    ".blockIdExt shard_proof:mode.0?bytes proof:mode.0?bytes state_proof:mode"
    ".1?bytes init_c7:mode.3?bytes lib_extras:mode.4?bytes exit_code:int"
    " result:mode.2?bytes = liteServer.RunMethodResult"
)

REQ_RES = {
    SCHEMA_ADNL_QUERY: SCHEMA_ADNL_ANSWER,
    SCHEMA_GET_MASTERCHAIN: SCHEMA_GET_MASTERCHAIN_RES
}
