from typing import Union, List, Optional
from abc import ABC


class BaseTL(ABC):
    def unpack(self, data_bytes: Optional[bytes], pos=0):
        pass

    def size(self):
        pass


class TLObject(BaseTL):
    """
    Base class for TL primitives such as:
    - int
    - long
    - int256
    """
    def __init__(self, size: int):
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


class TLInt256(TLObject):
    def __init__(self):
        super().__init__(32)

    def unpack(self, data_bytes, pos=0) -> str:
        return super().unpack(data_bytes, pos).hex()


class TLLong(TLObject):
    def __init__(self):
        super().__init__(8)

    def unpack(self, data_bytes, pos=0) -> str:
        return super().unpack(data_bytes, pos).hex()


class TLMetaObject(BaseTL):
    __size__ = 0

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

