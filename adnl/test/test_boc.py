import pytest

from adnl import boc

BOC = bytes.fromhex("b5ee9c7201010301000e000201c002010101ff0200060aaaaa")
CELL = b'\x02\x01\xc0\x02\x01\x01\x01\xff\x02\x00\x06\n\xaa\xaa'


def test_read_header():
    b = boc.Boc(BOC)
    b.read_header()
    assert b.size == 1
    assert b.flags == 0
    assert not b.has_index
    assert not b.has_cache_bits
    assert not b.has_crc32c
    assert b.off_bytes == 1
    assert b.cells == 3
    assert b.roots == 1
    assert b.absent == 0
    assert b.tot_cells_size == 14
    assert b.root_list == 0


def test_successfully_get_serialized_cells():
    b = boc.Boc(BOC)
    serialized = b.serialized_cell()
    assert serialized == CELL


def test_successfully_cell_deserialize():
    b = boc.Boc(BOC)
    root_cell = b.deserialize_cells()
    flat_list = root_cell.flat_list()
    assert len(flat_list) == 3
    assert flat_list[0].payload == b'\xc0'
    assert flat_list[1].payload == b'\xff'
    assert flat_list[2].payload == b'\x0a\xaa\xaa'


def test_successfully_cell_serialize():
    b = boc.Boc(BOC)
    root_cell = b.deserialize_cells()
    serialized_boc = b.serialize_cells(root_cell)
    assert serialized_boc == BOC

# b'\xb5\xee\x9cr\x01\x02\x03\x01\x00\x0e\x00\x02\x01\xc0\x02\x01\x01\x01\xff\x02\x00\x06\n\xaa\xaa'
# b'\xb5\xee\x9cr\x01\x01\x03\x01\x00\x0e\x00\x02\x01\xc0\x02\x01\x01\x01\xff\x02\x00\x06\n\xaa\xaa')