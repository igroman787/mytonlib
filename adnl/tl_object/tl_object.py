import copy
from typing import Union, List, Optional

from abc import ABC
from adnl import const


class BaseTL(ABC):
    def unpack(self, data_bytes: Optional[bytes], pos=0):
        pass

    def size(self):
        pass

    def pack(self, data) -> bytes:
        return b''


class TLObject(BaseTL):
    """
    Base class for TL primitives such as:
    - int
    - long
    - int256
    """
    def __init__(self, size: Optional[int]):
        self._size = size

    def unpack(self, data_bytes: Optional[bytes], pos=0) -> bytes:
        """
        Return slice of bytes
        :param data_bytes: bytes
        :param pos: start position
        :return:
        """
        offset = self.size() + pos
        return data_bytes[pos: offset]

    def pack(self, *args, **kwargs) -> bytes:
        return b''

    def size(self) -> int:
        """
        Return TL object size in bytes
        :return: bytes
        """
        return self._size

    def __repr__(self):
        return 'TLObject'


class TLInt(TLObject):
    def __init__(self):
        super().__init__(4)

    def unpack(self, data_bytes, pos=0) -> int:
        b = super().unpack(data_bytes, pos)
        return int.from_bytes(b, byteorder="little", signed=True)

    def pack(self, value: int) -> bytes:
        return int.to_bytes(
            value,
            self.size(),
            byteorder="little",
            signed=True
        )


class TLBytes(TLObject):
    def __init__(self, data: Optional[bytes] = b'', packed=False):
        super().__init__(None)
        self.data = data
        if self.data and not packed:
            self.pack(bytearray(self.data).hex())
        elif self.data and packed:
            self.unpack(self.data)

    def unpack(self, data_bytes: Optional[bytes], pos=0) -> bytes:
        data = bytearray(data_bytes)
        start = 1
        size = data[0:1]
        if size == const.BYTES_BIG_SIGN:
            size = data[1:4]
            start = len(size)
        self._size = int.from_bytes(size, byteorder='little')
        self.data = data[start: self._size + start]
        return bytes(self.data)

    def pack(self, hex_value: str) -> bytes:
        arr = bytearray.fromhex(hex_value)
        self._size = len(arr)
        if self._size > const.ONE_BYTE_LIMIT:
            # Make 3 bytes of size
            self._size = self._size.to_bytes(3, 'little')
            self._size = bytearray([const.BYTES_BIG_SIGN]) + self._size
            arr = self._size + arr
        else:
            arr.insert(0, self._size)
        # Try to pad bytes if it needs
        while len(arr) % 4:
            # Fill paddings
            arr.append(const.BYTES_PADDING)
        self.data = bytes(arr)
        return self.data

    def get_bytes(self) -> bytes:
        return bytes(self.data)


class TLInt256(TLObject):
    def __init__(self):
        super().__init__(32)

    def unpack(self, data_bytes, pos=0) -> str:
        return super().unpack(data_bytes, pos).hex()

    def pack(self, hex_value: str) -> bytearray:
        return bytearray.fromhex(hex_value)


class TLLong(TLObject):
    def __init__(self):
        super().__init__(8)

    def unpack(self, data_bytes, pos=0) -> str:
        return super().unpack(data_bytes, pos).hex()

    def pack(self, hex_value: str) -> bytearray:
        return bytearray.fromhex(hex_value)


class TLMetaObject(BaseTL):
    __size__ = 0
    __schema__ = None

    @classmethod
    def __fields_names__(cls) -> List[str]:
        return list(
            filter(
                lambda field: (
                    not field.startswith('_')
                    and not callable(getattr(cls, field))
                ),
                cls.__dict__
            )
        )

    @classmethod
    def __fields__(cls) -> List[Union[TLObject, 'TLMetaObject']]:
        fields = []
        for name in cls.__fields_names__():
            fields.append(getattr(cls, name))
        return fields

    @classmethod
    def calc_size(cls):
        sizes = []
        for f in cls.__fields__():
            if isinstance(f, TLMetaObject):
                f.calc_size()
                sizes.append(f.size())
            elif isinstance(f, TLObject):
                sizes.append(f.size())

        setattr(cls, '__size__', sum(sizes))

    @classmethod
    def size(cls):
        return cls.__size__

    @classmethod
    def unpack(cls, data_bytes: Optional[bytes], pos: int = 0) -> dict:
        cls.calc_size()
        if not data_bytes:
            return {}

        result = {}
        cur_pos = pos
        field_names = cls.__fields_names__()
        for field_name in field_names:
            field = getattr(cls, field_name)
            result[field_name] = field.unpack(data_bytes, cur_pos)
            cur_pos += field.size()
        return result

    @classmethod
    def pack(cls, **kwargs) -> bytes:
        result = b''
        field_names = cls.__fields_names__()
        for field_name in field_names:
            current_data = kwargs.get(field_name)
            if not current_data:
                raise Exception(f'Field {field_name} required')

            field = getattr(cls, field_name)
            if isinstance(field, TLMetaObject):
                result += field.pack(**current_data)
            else:
                result += field.pack(current_data)
        return result

    def validate_response(self, data: bytes):
        raise Exception('Not implemented')

    @staticmethod
    def response_schema_id(data: bytes) -> bytes:
        return data[0:4]
