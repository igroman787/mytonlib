from pytest import fixture
from adnl import tl_object
from adnl import const

SMALL_SIZE = 253
BIG_SIZE = SMALL_SIZE * 2


@fixture
def package_small():
    data = [i for i in range(1, SMALL_SIZE)]
    return bytearray(data)


@fixture
def package_big(package_small):
    return package_small * 2


def test_pack_bytes_small(package_small):
    b = tl_object.TLBytes()
    h = package_small.hex()
    package = bytearray(b.pack(h))
    size = package.pop(0)
    flt = filter(const.BYTES_PADDING.__ne__, package)
    package = bytearray(flt)
    assert len(package_small) == size
    assert package_small == package


def test_pack_bytes_big(package_big):
    b = tl_object.TLBytes()
    h = package_big.hex()
    package = bytearray(b.pack(h))
    sign = package.pop(0)
    size = package[:3]
    data = package[3:]
    size = int.from_bytes(size, byteorder='little', signed=True)
    flt = filter(const.BYTES_PADDING.__ne__, data)
    package = bytearray(flt)
    assert sign == const.BYTES_BIG_SIGN
    assert len(package_big) == size
    assert package_big == package
