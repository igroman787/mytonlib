__version__ = 0.1

from . import models
from . import tl_object
"""
TL object parser

How to use
Example:
-------------------------------------------------------------------------------
from adnl.tl_object import models

# read bytes from liteserver
>> rdata: bytes = [lite server query result]

# get response data payload
>> data: bytes = rdata[4:]

# pass byte-like payload to data model
>> result: dict = models.MasterchainInfo.unpack(data)

# use result dictionary as you wish
>> print(result)
{ ... }

# reverse serializing
data: bytes = model.MasterchainInfo.pack(result)
-------------------------------------------------------------------------------
"""
