import math
from typing import Union
from typing import Tuple
from typing import List
from typing import Dict

from .cell import Cell
from .bits import Bits

BOC_IDX = '68ff65f3'
BOC_IDX_CRC32C = 'acc3a728'
BOC_GENERIC = 'b5ee9c72'
DEF_SIZE = 0xffff


def if_valid(fun):
    def inner(self, *args, **kwargs):
        if not self.valid:
            raise Exception('BOC invalid')
        return fun(self, *args, **kwargs)
    return inner


class Boc:
    def __init__(self, data: bytes):
        self.size = min(len(data), DEF_SIZE)
        self.valid = self.size > 4
        self.data = data

        self.headers = [
            bytes.fromhex(BOC_GENERIC),
            bytes.fromhex(BOC_IDX_CRC32C),
            bytes.fromhex(BOC_IDX)
        ]

        self.has_crc32c = False
        self.has_index = False
        self.has_cache_bits = False
        self.has_roots = False
        self.flags = 0
        self.off_bytes = 0
        self.cells = None
        self.roots = None
        self.absent = None
        self.tot_cells_size = None
        self.root_list = None
        self.conv_args = {'byteorder': 'little', 'signed': False}
        self.read_header()

    def has_boc_generic(self) -> bool:
        return self.data[:4] == bytes.fromhex(BOC_GENERIC)

    def read_int(self, pos: int, count: int):
        return int.from_bytes(self.data[pos: count], **self.conv_args)

    def get_magic(self, as_int: bool = False) -> Union[bytes, int]:
        magic = self.data[:4]
        if as_int:
            return int.from_bytes(magic, byteorder='little', signed=True)
        return magic

    def has_magic(self):
        return self.get_magic() in self.headers

    def calc_size_flags(self):
        b = self.get_magic(as_int=True)
        self.has_index = (b >> 7) % 2 == 1
        self.has_crc32c = (b >> 6) % 2 == 1
        self.has_cache_bits = (b >> 5) % 2 == 1

    def set_default_flags(self):
        self.has_index = True
        self.has_crc32c = bytes.fromhex(BOC_IDX_CRC32C)
        self.has_cache_bits = bytes.fromhex(BOC_IDX_CRC32C)

    @staticmethod
    def __calculate_flags(first_meta_byte: int) -> List[bool]:
        """
        Returns flags of cell
        :param first_meta_byte: First byte of cell 2bytes metadata
        :return:
        """
        bits = Bits(first_meta_byte)
        return [bits.is_set(i) for i in range(5)]

    @staticmethod
    def __calculate_ref_count(first_meta_byte: int) -> int:
        """
        Returns count of references for serialized cell
        :param first_meta_byte: First byte of cell 2bytes metadata
        :return:
        """
        bits = Bits(first_meta_byte)
        bits = [
            1 if bits.is_set(i) else 0
            for i in range(5, 8, 1)
        ]
        num = 0b0
        for i in range(2):
            if bits[i]:
                num |= (1 << i)
        return num

    @staticmethod
    def flags_and_ref_count(first_meta_byte: int) -> Tuple[List[bool], int]:
        bits = Bits(first_meta_byte)
        flags, ref_count = bits.split(3)
        flag_bits = Bits(flags)
        flags = [flag_bits.is_set(i) for i in range(5)]
        return flags, ref_count

    @staticmethod
    def build_flags_and_ref_count(cell: Cell) -> int:
        bits = Bits()
        # todo: check algorithm to calc flags in cell
        flags = cell.get_flags(integer=True)
        flags = ''.join([str(f) for f in flags])
        flags = bits.int_from_bin_str(flags)
        return bits.merge(flags, cell.ref_count, pos=5)

    @staticmethod
    def payload(cell_slice: bytes, data_length: int) -> bytes:
        return cell_slice[2:2+data_length]

    def extract_flags_and_size(self, data: bytes) -> int:
        """
        0b
        0 _ has_idx
        0 _ has_crc32
        0 _ has_cache_bits
        0 _ flags
        0 _|
        0 _ size
        0 _|
        0 _|
        :param data:
        :return:
        """
        data_i = int.from_bytes(data, **self.conv_args)
        bits = Bits(data_i)
        if data_i > 1:
            self.has_index = bits.is_set(0)
            self.has_crc32c = bits.is_set(1)
            self.has_cache_bits = bits.is_set(2)
            self.flags = int.from_bytes(data[3:5], **self.conv_args)
        self.size = int.from_bytes(data[-3:], **self.conv_args)
        return self.size

    def read_cell(self, data: bytes) -> Cell:
        """
        0201 c0 0201
        0101 ff 02
        0006 0aaaaa
        :param data:
        :return:
        """
        # reading of 5 bits of flags
        data_length = int.from_bytes(data[1:2], **self.conv_args)
        # read references ids
        ref_ids = []
        flags_sz_info = int.from_bytes(
            data[0:1],
            byteorder='little',
            signed=False
        )
        flags, ref_count = self.flags_and_ref_count(flags_sz_info)
        ref_pos = data_length + 2
        for i in range(ref_count):
            pos = ref_pos + i
            ref_ids.append(int.from_bytes(data[pos:pos+1], **self.conv_args))

        slice_size = sum([
            2,  # flag and size
            data_length,  # payload length
            ref_count  # size of references info
        ])

        return Cell(
            ref_count=ref_count,
            flags=flags,
            length=data_length,
            ref_ids=ref_ids,
            serialized=data[:slice_size],
            payload=self.payload(data, data_length)
        )

    def pack_cell(self, cell) -> bytes:
        """
        Pack cell without references, used to pack cell from flat list to boc
        :param cell:
        :return:
        """
        pass

    def extract_cell_count(self, data):
        self.cells = int.from_bytes(data, **self.conv_args)

    def read_header(self):
        head = self.data[0:4]  # uint32
        cells_size = self.extract_flags_and_size(self.data[4:5])
        self.off_bytes = self.read_int(5, 6)
        self.cells = self.read_int(6, 6 + cells_size)
        self.roots = self.read_int(7, 7 + cells_size)
        self.absent = self.read_int(8, 8 + cells_size)
        self.tot_cells_size = self.read_int(9, 9 + self.off_bytes)
        self.root_list = self.read_int(10, 10 + self.size)

    def build_with_header(self, cells_count: int, serialized: bytes) -> bytes:
        bits = Bits()
        # flags = [0, 0, 0, 0, 0]
        # bits count to store count of cells
        bits_size = math.ceil(cells_count/8)
        values = [
            # flags and size
            bits.merge(0, bits_size, pos=3),
            # bits to store serialized cells size
            math.ceil(len(serialized).bit_length() / 8),
            # cells count
            cells_count,
            # root_count
            1,
            # absent
            0,
            # bytes size of serialized cells
            len(serialized),
            # root index
            0
        ]
        res = bytes.fromhex(BOC_GENERIC)
        for val in values:
            res += val.to_bytes(1, **self.conv_args)
        res += serialized
        return res

    def serialized_cell(self) -> bytes:
        return self.data[-self.tot_cells_size:]

    @staticmethod
    def build_cell_with_refs(cells_dict: Dict[int, Cell]) -> Cell:
        for cell_id in cells_dict:
            cell = cells_dict[cell_id]
            ref_ids = cell.ref_ids
            for ref_id in ref_ids:
                cell.add_ref(cells_dict[ref_id])
        return cells_dict[0]

    def deserialize_cells(self) -> Cell:
        self.read_header()
        cells = {}
        data_slice = self.serialized_cell()
        for i in range(self.cells):
            cell = self.read_cell(data_slice)
            cells.update({i: cell})
            cell_slice_len = len(cell.serialized)
            data_slice = data_slice[cell_slice_len:]
        cell = self.build_cell_with_refs(cells)
        return cell

    def serialize_cells(self, cell: Cell) -> bytes:
        flat_list = cell.flat_list()
        packed = b''
        for cell in flat_list:
            size_and_flags = self.build_flags_and_ref_count(cell)
            packed += size_and_flags.to_bytes(1, **self.conv_args)
            packed += cell.length.to_bytes(1, **self.conv_args)
            packed += cell.payload
            for ref_id in cell.ref_ids:
                packed += ref_id.to_bytes(1, **self.conv_args)
        res = self.build_with_header(len(flat_list), packed)
        return res
