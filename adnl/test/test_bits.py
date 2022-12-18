import pytest

from adnl.boc.bits import Bits


@pytest.mark.parametrize('value,pos,left_expected,right_expected', (
    (0b11001111, 3, 0b110, 0b01111),
    (0b11110000, 4, 0b1111, 0b0000),
    (0b11110000, None, 0b1111, 0b0000),
    (2, 3, 0, 2)
))
def test_split_bits(value, pos, left_expected, right_expected):
    bits = Bits(value)
    left, right = bits.split(pos)
    assert left == left_expected
    assert right == right_expected


@pytest.mark.parametrize('idx', [*range(8)])
def test_successfully_bit_set(idx):
    bits = Bits(0b00000000)
    bits.set(idx)
    assert bits.is_set(idx)


@pytest.mark.parametrize('idx', [*range(8)])
def test_successfully_bit_clear(idx):
    bits = Bits(0b11111111)
    bits.clear(idx)
    assert not bits.is_set(idx)


@pytest.mark.parametrize('left,right,pos,expected', (
        (0b11011, 0b010, 5, 0b11011010),
        (0b1110, 0b1000, 4, 0b11101000),
        (0b1000, 0b0001, 4, 0b10000001),
        (0b1, 0b1, 4, 0b00010001)
))
def test_successfully_merge(left, right, pos, expected):
    bits = Bits()
    merged = bits.merge(left, right, pos=pos)
    assert merged == expected
