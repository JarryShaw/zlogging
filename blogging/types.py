# -*- coding: utf-8 -*-
"""Bro/Zeek data types."""

import abc
import ctypes
import decimal
import datetime
import enum
import ipaddress
import warnings

import blogging.typing as typing
from blogging.enum import globals as enum_generator

__all__ = [
    'AddrType', 'BoolType', 'CountType', 'DoubleType', 'EnumType',
    'IntervalType', 'IntType', 'PortType', 'SetType', 'StringType',
    'SubnetType', 'TimeType', 'VectorType',
]


def decimal_toascii(data: typing.Decimal) -> str:
    """Convert ``decimal.Decimal`` to ASCII."""
    tpl: decimal.DecimalTuple = data.as_tuple()

    exp = tpl.exponent
    if exp >= 0:
        return '%s%s%s.000000' % ('-' if tpl.sign else '',
                                  ''.join(map(str, tpl.digits)),
                                  '0' * exp)

    expabs = abs(exp)
    dgtlen = len(tpl.digits)
    if expabs >= dgtlen:
        diff = expabs - dgtlen
        if diff == 0:
            diff = 1
        return '%s%s.%s%s' % ('-' if tpl.sign else '',
                              '0' * diff,
                              ''.join(map(str, tpl.digits[:6])),
                              '0' * (6 - dgtlen))

    buf_int = ''
    buf_flt = ''
    for index, digit in enumerate(reversed(tpl.digits), start=1):
        if index <= expabs:
            buf_flt = str(digit) + buf_flt
        else:
            buf_int = str(digit) + buf_int
    return '%s%s.%s%s' % ('-' if tpl.sign else '',
                          buf_int, buf_flt[:6],
                          '0' * (6 - len(buf_flt)))


def float_toascii(data: float) -> str:
    """Convert ``float`` to ASCII."""
    int_part, flt_part = str(data).split('.')
    return '%s.%s%s' % (int_part,
                        flt_part[:6],
                        '0' * (6 - len(flt_part)))


class ZeekValueError(ValueError):
    """Invalid Bro/Zeek data value."""


class ZeekValueWarning(UserWarning):
    """Dubious Bro/Zeek data value."""


class Type(metaclass=abc.ABCMeta):
    """Base Bro/Zeek data type.

    Attributes:
        empty_field (:obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`str`, optional): placeholder for unset field
        set_seperator (:obj:`str`, optional): seperator for set/list fields

    """

    @property
    @abc.abstractmethod
    def python_type(self):
        """type: corresponding Python type annotation."""

    @property
    @abc.abstractmethod
    def zeek_type(self):
        """str: corresponding Zeek type name."""

    @property
    def bro_type(self):
        """str: corresponding Bro type name."""
        warnings.warn("Use of 'bro_type' is deprecated. "
                      "Please use 'zeek_type' instead.", DeprecationWarning)
        return self.zeek_type

    def __init__(self,
                 empty_field: typing.Optional[str] = None,
                 unset_field: typing.Optional[str] = None,
                 set_seperator: typing.Optional[str] = None):
        """Initialisation.

        Args:
            empty_field (:obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`str`, optional): placeholder for unset field
            set_seperator (:obj:`str`, optional): seperator for set/vector fields

        """
        if empty_field is None:
            empty_field = '(empty)'
        if unset_field is None:
            unset_field = '-'
        if set_seperator is None:
            set_seperator = ','

        self.empty_field = empty_field
        self.unset_field = unset_field
        self.set_seperator = set_seperator

    def __call__(self, data: typing.Any) -> typing.Any:
        """Parse ``data`` from string."""
        return self.parse(data)

    @abc.abstractmethod
    def parse(self, data: bytes) -> typing.Any:
        """Parse ``data`` from string."""

    @abc.abstractmethod
    def tojson(self, data: typing.Any) -> typing.Any:
        """Serialize ``data`` as JSON log format."""

    @abc.abstractmethod
    def toascii(self, data: typing.Any) -> str:
        """Serialize ``data`` as ASCII log format."""


class BoolType(Type):
    """Bro/Zeek ``bool`` data type."""

    @property
    def python_type(self):
        return bool

    @property
    def zeek_type(self):
        return 'bool'

    def parse(self, data: bytes) -> typing.Union[None, bool]:
        if data == self.unset_field:
            return None
        if data == 'T':
            return True
        if data == 'F':
            return False
        raise ZeekValueError('invalid bool value: %s' % data)

    def tojson(self, data: typing.Union[None, bool]) -> typing.Union[None, bool]:
        return data

    def toascii(self, data: typing.Union[None, bool]) -> str:
        if data is None:
            return self.unset_field
        return 'T' if data else 'F'


class CountType(Type):
    """Bro/Zeek ``count`` data type."""

    @property
    def python_type(self):
        return typing.uint64

    @property
    def zeek_type(self):
        return 'count'

    def parse(self, data: bytes) -> typing.Union[None, typing.uint64]:
        if data == self.unset_field:
            return None
        return ctypes.c_uint64(int(data))

    def tojson(self, data: typing.Union[None, typing.uint64]) -> typing.Union[None, typing.uint64]:
        if data is None:
            return data
        return data.value

    def toascii(self, data: typing.Union[None, typing.uint64]) -> str:
        if data is None:
            return self.unset_field
        return str(data.value)


class IntType(Type):
    """Bro/Zeek ``int`` data type."""

    @property
    def python_type(self):
        return typing.int64

    @property
    def zeek_type(self):
        return 'int'

    def parse(self, data: bytes) -> typing.Union[None, typing.int64]:
        if data == self.unset_field:
            return None
        return ctypes.c_int64(int(data))

    def tojson(self, data: typing.Union[None, typing.int64]) -> typing.Union[None, typing.int64]:
        if data is None:
            return data
        return data.value

    def toascii(self, data: typing.Union[None, typing.int64]) -> str:
        if data is None:
            return self.unset_field
        return str(data.value)


class DoubleType(Type):
    """Bro/Zeek ``double`` data type."""

    @property
    def python_type(self):
        return decimal.Decimal

    @property
    def zeek_type(self):
        return 'double'

    def parse(self, data: bytes) -> typing.Union[None, typing.Decimal]:
        if data == self.unset_field:
            return None
        with decimal.localcontext() as ctx:
            ctx.prec = 6
            value = decimal.Decimal(data.decode())
        return value

    def tojson(self, data: typing.Union[None, typing.Decimal]) -> typing.Union[None, typing.Decimal]:
        if data is None:
            return data
        return float(data)

    def toascii(self, data: typing.Union[None, typing.Decimal]) -> str:
        if data is None:
            return self.unset_field
        return decimal_toascii(data)


class TimeType(Type):
    """Bro/Zeek ``time`` data type."""

    @property
    def python_type(self):
        return datetime.datetime

    @property
    def zeek_type(self):
        return 'time'

    def parse(self, data: bytes) -> typing.Union[None, typing.DateTime]:
        if data == self.unset_field:
            return None
        with decimal.localcontext() as ctx:
            ctx.prec = 6
            value = decimal.Decimal(data.decode())
        return datetime.datetime.fromtimestamp(value)

    def tojson(self, data: typing.Union[None, typing.DateTime]) -> typing.Union[None, float]:
        if data is None:
            return data
        return data.timestamp()

    def toascii(self, data: typing.Union[None, typing.DateTime]) -> str:
        if data is None:
            return self.unset_field
        return float_toascii(data.timestamp())


class IntervalType(Type):
    """Bro/Zeek ``interval`` data type."""

    @property
    def python_type(self):
        return datetime.timedelta

    @property
    def zeek_type(self):
        return 'interval'

    def parse(self, data: bytes) -> typing.Union[None, typing.TimeDelta]:
        if data == self.unset_field:
            return None
        int_part, flt_part = data.split(b'.')
        return datetime.timedelta(seconds=int_part,
                                  microseconds=flt_part[:3],
                                  milliseconds=flt_part[3:])

    def tojson(self, data: typing.Union[None, typing.TimeDelta]) -> typing.Union[None, float]:
        if data is None:
            return data
        return data.total_seconds()

    def toascii(self, data: typing.Union[None, typing.TimeDelta]) -> str:
        if data is None:
            return self.unset_field
        return float_toascii(data.total_seconds())


class StringType(Type):
    """Bro/Zeek ``string`` data type."""

    @property
    def python_type(self):
        return str

    @property
    def zeek_type(self):
        return 'string'

    def parse(self, data: bytes) -> typing.Union[None, str]:
        if data == self.empty_field:
            return str()
        if data == self.unset_field:
            return None
        return data.decode('unicode_escape')

    def tojson(self, data: typing.Union[None, str]) -> typing.Union[None, str]:
        return data

    def toascii(self, data: typing.Union[None, str]) -> str:
        if data is None:
            return self.unset_field
        if data:
            return data
        return self.empty_field


class AddrType(Type):
    """Bro/Zeek ``addr`` data type."""

    @property
    def python_type(self):
        return typing.IPAddress

    @property
    def zeek_type(self):
        return 'addr'

    def parse(self, data: bytes) -> typing.Union[None, typing.IPAddress]:
        if data == self.unset_field:
            return None
        return ipaddress.ip_address(data.decode())

    def tojson(self, data: typing.Union[None, typing.IPAddress]) -> typing.Union[None, str]:
        if data is None:
            return data
        return str(data)

    def toascii(self, data: typing.Union[None, typing.IPAddress]) -> str:
        if data is None:
            return self.unset_field
        return str(data)


class PortType(Type):
    """Bro/Zeek ``port`` data type."""

    @property
    def python_type(self):
        return typing.uint16

    @property
    def zeek_type(self):
        return 'port'

    def parse(self, data: bytes) -> typing.Union[None, typing.uint16]:
        if data == self.unset_field:
            return None
        return ctypes.c_uint16(int(data))

    def tojson(self, data: typing.Union[None, typing.uint16]) -> typing.Union[None, typing.uint16]:
        if data is None:
            return data
        return data.value

    def toascii(self, data: typing.Union[None, typing.uint16]) -> typing.Union[None, typing.uint16]:
        if data is None:
            return self.unset_field
        return str(data.value)


class SubnetType(Type):
    """Bro/Zeek ``subnet`` data type."""

    @property
    def python_type(self):
        return typing.IPNetwork

    @property
    def zeek_type(self):
        return 'port'

    def parse(self, data: bytes) -> typing.Union[None, typing.IPNetwork]:
        if data == self.unset_field:
            return None
        return ipaddress.ip_network(data.decode())

    def tojson(self, data: typing.Union[None, typing.IPNetwork]) -> typing.Union[None, str]:
        if data is None:
            return data
        return str(data)

    def toascii(self, data: typing.Union[None, typing.IPNetwork]) -> str:
        if data is None:
            return self.unset_field
        return str(data)


class EnumType(Type):
    """Bro/Zeek ``enum`` data type.

    Attributes:
        empty_field (:obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`str`, optional): placeholder for unset field
        set_seperator (:obj:`str`, optional): seperator for set/list fields
        enum_namespace (:obj:`Dict[str, Enum]`): global namespace for ``enum`` data type

    """

    @property
    def python_type(self):
        return typing.Enum

    @property
    def zeek_type(self):
        return 'enum'

    def __init__(self, empty_field=None, unset_field=None, set_seperator=None,
                 namespaces: typing.Optional[typing.List[str]] = None, bare: bool = False):
        """Initialisation.

        Args:
            empty_field (:obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`str`, optional): placeholder for unset field
            set_seperator (:obj:`str`, optional): seperator for set/vector fields
            namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            bare (:obj:`bool`, optional): if ``True``, do not load ``zeek`` namespace by default

        """
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_seperator=set_seperator)

        if namespaces is None:
            namespaces = list()
        self.enum_namespace = enum_generator(*namespaces, bare=bare)

    def parse(self, data: bytes) -> typing.Union[None, typing.Enum]:
        if data == self.unset_field:
            return None
        data_str = data.decode()
        item = self.enum_namespace.get()
        if item is None:
            warnings.warn('unrecognised enum value: %s' % data_str, ZeekValueWarning)
            return enum.IntFlag('<unknown>', [(data_str, 0)])[data_str]
        return item

    def tojson(self, data: typing.Union[None, typing.Enum]) -> typing.Union[None, str]:
        if data is None:
            return data
        return data.name

    def toascii(self, data: typing.Union[None, typing.Enum]) -> str:
        if data is None:
            return self.unset_field
        return data.name


class SetType(Type):
    """Bro/Zeek ``set`` data type.

    Attributes:
        empty_field (:obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`str`, optional): placeholder for unset field
        set_seperator (:obj:`str`, optional): seperator for set/list fields
        element_type (:obj:`Type` instance), data type of container's elements

    """

    @property
    def python_type(self):
        return typing.Set[typing.Data]

    @property
    def zeek_type(self):
        return 'set'

    def __init__(self, empty_field=None, unset_field=None, set_seperator=None,
                 element_type: Type = None):
        """Initialisation.

        Args:
            empty_field (:obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`str`, optional): placeholder for unset field
            set_seperator (:obj:`str`, optional): seperator for set/vector fields
            namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            element_type (:obj:`Type` instance, required), data type of container's elements

        """
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_seperator=set_seperator)

        if element_type is None:
            raise ZeekValueError("__init__() missing 1 required positional argument: 'element_type'")
        if not isinstance(element_type, Type):
            raise ZeekValueError('invalid element type: %r' % type(element_type).__name__)
        self.element_type = element_type

    def parse(self, data: bytes) -> typing.Union[None, typing.Set[typing.Data]]:
        if data == self.unset_field:
            return None
        if data == self.empty_field:
            return set()
        return set(self.element_type(element) for element in data.split(self.set_seperator))

    def tojson(self, data: typing.Union[None, typing.Set[typing.Data]]) -> typing.Union[None, typing.List[typing.Data]]:
        if data is None:
            return None
        return list(self.element_type.tojson(element) for element in data)

    def toascii(self, data: typing.Union[None, typing.Set[typing.Data]]) -> str:
        if data is None:
            return self.unset_field
        if not data:
            return self.empty_field
        return self.set_seperator.join(self.element_type.toascii(element) for element in data)


class VectorType(Type):
    """Bro/Zeek ``vector`` data type.

    Attributes:
        empty_field (:obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`str`, optional): placeholder for unset field
        set_seperator (:obj:`str`, optional): seperator for set/list fields
        element_type (:obj:`Type` instance), data type of container's elements

    """

    @property
    def python_type(self):
        return typing.List[typing.Data]

    @property
    def zeek_type(self):
        return 'vector'

    def __init__(self, empty_field=None, unset_field=None, set_seperator=None,
                 element_type: Type = None):
        """Initialisation.

        Args:
            empty_field (:obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`str`, optional): placeholder for unset field
            set_seperator (:obj:`str`, optional): seperator for set/vector fields
            namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            element_type (:obj:`Type` instance, required), data type of container's elements

        """
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_seperator=set_seperator)

        if element_type is None:
            raise ZeekValueError('__init__() missing 1 required positional argument: %r' % element_type)
        if not isinstance(element_type, Type):
            raise ZeekValueError('invalid element type: %r' % type(element_type).__name__)
        self.element_type = element_type

    def parse(self, data: bytes) -> typing.Union[None, typing.List[typing.Data]]:
        if data == self.unset_field:
            return None
        if data == self.empty_field:
            return list()
        return list(self.element_type(element) for element in data.split(self.set_seperator))

    def tojson(self, data: typing.Union[None, typing.List[typing.Data]]) -> typing.Union[None, typing.List[typing.Data]]:  # pylint: disable=line-too-long
        if data is None:
            return None
        return list(self.element_type.tojson(element) for element in data)

    def toascii(self, data: typing.Union[None, typing.List[typing.Data]]) -> str:
        if data is None:
            return self.unset_field
        if not data:
            return self.empty_field
        return self.set_seperator.join(self.element_type.toascii(element) for element in data)
