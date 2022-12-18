import json

import pytest
from adnl.tl_object import models

DATA = (
        b'\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x80xB#\x00Y\xd0Ef\xc5'
        b'\xab\x9ev@\x87 \xff\x91\r\x84\xac\xa9\xc6[T\xf6\x91\n{'
        b'DZ\xa6\xed\xf29\xa5R\x1ei\x13\xa7\xf1\xf8k\x8a\xd9=\xae\xf7\xde\xc7'
        b'~-\x00A\xbc\x0b}\xf7\xc2\x8b[\xc3{'
        b'\x9bk\xb1\xce\xdb\x92\xd7\x8cp1\xa5\x81\xe2\xd9c.\x83\xb5+x\xf1'
        b'\xcfG\x0e\x0c\x98\xaf\x9a\x88\x98\xbcU\xeb\xceQ\xdfe\xff\xff\xff'
        b'\xff\x82?\x81\xf3\x06\xff\x02iO\x93\\\xf5\x02\x15H\xe3\xce+\x86\xb5'
        b')\x81*\xf6\xa1!H\x87\x9e\x95\xa1('
        b'g\xe2\n\xc1\x84\xb9\xe09\xa6&g\xac\xc3\xf9\xc0\x0f\x90\xf3Y\xa7g8'
        b'#3y\xef\xa4v\x04\x98\x0c\xe8'
)

MASTERCHAIN = {
    'last': {
        'workchain': -1,
        'shard': '0000000000000080',
        'seqno': 2310776,
        'root_hash': (
            '59d04566c5ab9e76408720ff910d84aca9c65b54f6910a7b445aa6edf239a552'
        ),
        'file_hash': (
            '1e6913a7f1f86b8ad93daef7dec77e2d0041bc0b7df7c28b5bc37b9b6bb1cedb'
        )
        },
    'state_root_hash': (
        '92d78c7031a581e2d9632e83b52b78f1cf470e0c98af9a8898bc55ebce51df65'
    ),
    'init': {
        'workchain': -1,
        'root_hash': (
            '823f81f306ff02694f935cf5021548e3ce2b86b529812af6a12148879e95a128'
        ),
        'file_hash': (
            '67e20ac184b9e039a62667acc3f9c00f90f359a76738233379efa47604980ce8'
        )
    }
}


def test_deserialize_masterchain():
    parsed_data = models.MasterchainInfo.unpack(DATA)
    assert json.dumps(parsed_data) == json.dumps(MASTERCHAIN)


def test_serialize_masterchain():
    data = models.MasterchainInfo.pack(**MASTERCHAIN)
    assert data == DATA
