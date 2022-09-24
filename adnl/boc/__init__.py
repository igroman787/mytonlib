from .boc import *

"""
BOC serializer/deserializer

Example:

>> from boc import Boc

>> BOC = bytes.fromhex("b5ee9c7201010301000e000201c002010101ff0200060aaaaa")
>> b = Boc(BOC)
>> root_cell = b.deserialize_cells()

>> serialized = b.serialize_cells(root_cell)
>> print(hex(serialized))
<< b5ee9c7201010301000e000201c002010101ff0200060aaaaa
"""