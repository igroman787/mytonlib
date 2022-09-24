from typing import List
from typing import Optional
from typing import Tuple


class Bits:
    def __init__(self, d: int = 0):
        if d > 0xff:
            msg = f'To long bytes object, max = 0xFF, actual = {hex(d)}'
            raise Exception(msg)
        self.__byte = d

    def as_bytes(self) -> bytes:
        return self.__byte.to_bytes(1, byteorder='little', signed=False)

    def as_int(self) -> int:
        return self.__byte

    @staticmethod
    def int_from_bin_str(bin_str: str) -> int:
        length = len(bin_str)
        num = 0
        for i in range(length):
            num += int(bin_str[i])
            num *= 2
        return int(num/2)

    def set(self, n: int):
        self.__byte |= (1 << n)
        return self.__byte

    def clear(self, n: int):
        self.__byte &= ~(1 << n)
        return self.__byte

    def is_set(self, n) -> bool:
        return bool((self.__byte >> n) & 1)

    def split(self, split_pos: Optional[int] = None) -> Tuple[int, int]:
        str_repr = bin(self.__byte)[2:].zfill(8)
        pos = split_pos if split_pos else 4
        left = self.int_from_bin_str(str_repr[:pos])
        right = self.int_from_bin_str(str_repr[pos:])
        return left, right

    def merge(self, left: int, right: int, pos: int = 4) -> int:
        left_ln = pos
        right_ln = 8 - pos
        repr_left = bin(left)[2:].zfill(left_ln)
        repr_right = bin(right)[2:].zfill(right_ln)
        full = repr_left + repr_right
        return self.int_from_bin_str(full)

