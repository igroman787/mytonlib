from typing import List
from typing import Optional
from typing import Union


class Cell:
    def __init__(
            self,
            ref_count: int = 0,
            length: int = 0,
            ref_ids: Optional[List[int]] = None,
            flags: Optional[List[bool]] = None,
            serialized: Optional[bytes] = None,
            payload: Optional[bytes] = None
    ):
        self.ref_count = ref_count
        self.length = length
        self.ref_ids = ref_ids
        self.flags = flags
        self.serialized = serialized
        self.payload = payload
        self.__ref_list = []
        self.__ref_list_cnt = 0

    def add_ref(self, cell: 'Cell') -> None:
        self.__ref_list.append(cell)
        self.ref_count = len(self.__ref_list)

    def get_flags(self, integer=False) -> List[Union[bool, int]]:
        if integer:
            return [int(flag) for flag in self.flags]
        return self.flags

    def __get_refs(self, cell: 'Cell') -> List['Cell']:
        arr = [cell]
        ref_iter = iter(cell)
        ref_cell = next(ref_iter, None)
        while ref_cell:
            arr.append(ref_cell)
            arr += self.__get_refs(ref_cell)
            ref_cell = next(ref_iter, None)
        return arr

    def flat_list(self):
        cells = self.__get_refs(self)
        cells = set(cells)
        cells = sorted(cells, key=lambda c: c.ref_count, reverse=True)
        return cells

    def __iter__(self):
        return self

    def __next__(self):
        try:
            ref = self.__ref_list[self.__ref_list_cnt]
            self.__ref_list_cnt += 1
            return ref
        except IndexError:
            self.__ref_list_cnt = 0
            raise StopIteration

    def __eq__(self, other: 'Cell') -> bool:
        return self.payload == other.payload

    def __hash__(self):
        return hash(str(self))

    def __str__(self):
        i = int.from_bytes(self.payload, byteorder='little', signed=False)
        return hex(i)

    def __repr__(self):
        return str(self)
