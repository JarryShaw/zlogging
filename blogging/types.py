# -*- coding: utf-8 -*-
"""Bro/Zeek data types."""

import abc
import ctypes
import datetime
import decimal
import json
import enum
import ipaddress
import warnings

import blogging._typing as typing
from blogging._aux import decimal_toascii, float_toascii
from blogging._exc import BroDeprecationWarning, ZeekValueError, ZeekValueWarning, ZeekTypeError
from blogging.enum import globals as enum_generator

__all__ = [
    'AddrType', 'BoolType', 'CountType', 'DoubleType', 'EnumType',
    'IntervalType', 'IntType', 'PortType', 'SetType', 'StringType',
    'SubnetType', 'TimeType', 'VectorType',
]


class Type(metaclass=abc.ABCMeta):
    """Base Bro/Zeek data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    @abc.abstractmethod
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""

    @property
    @abc.abstractmethod
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""

    @property
    def bro_type(self) -> str:
        """str: corresponding Bro type name."""
        warnings.warn("Use of 'bro_type' is deprecated. "
                      "Please use 'zeek_type' instead.", BroDeprecationWarning)
        return self.zeek_type

    def __init__(self,
                 empty_field: typing.Optional[typing.AnyStr] = None,
                 unset_field: typing.Optional[typing.AnyStr] = None,
                 set_separator: typing.Optional[typing.AnyStr] = None):
        """Initialisation.

        Args:
            empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
            set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields

        """
        if empty_field is None:
            empty_field = b'(empty)'
        if unset_field is None:
            unset_field = b'-'
        if set_separator is None:
            set_separator = b','

        if isinstance(empty_field, str):
            self.empty_field = empty_field.encode('ascii')
            self.str_empty_field = empty_field
        else:
            self.empty_field = empty_field
            self.str_empty_field = empty_field.decode('ascii')

        if isinstance(unset_field, str):
            self.unset_field = unset_field.encode('ascii')
            self.str_unset_field = unset_field
        else:
            self.unset_field = unset_field
            self.str_unset_field = unset_field.decode('ascii')

        if isinstance(set_separator, str):
            self.set_separator = set_separator.encode('ascii')
            self.str_set_separator = set_separator
        else:
            self.set_separator = set_separator
            self.str_set_separator = set_separator.decode('ascii')

    def __call__(self, data: bytes) -> typing.Any:
        """Parse ``data`` from string."""
        return self.parse(data)

    def __str__(self) -> str:
        return self.zeek_type

    def __repr__(self) -> str:
        return '%s(empty_field=%s, unset_field=%s, set_separator=%s)' % (type(self).__name__, self.empty_field,
                                                                         self.unset_field, self.set_separator)

    @abc.abstractmethod
    def parse(self, data: typing.Union[typing.AnyStr, typing.Any]) -> typing.Any:
        """Parse ``data`` from string."""

    @abc.abstractmethod
    def tojson(self, data: typing.Any) -> typing.Any:
        """Serialize ``data`` as JSON log format."""

    @abc.abstractmethod
    def toascii(self, data: typing.Any) -> str:
        """Serialize ``data`` as ASCII log format."""


class _SimpleType(Type):  # pylint: disable=abstract-method
    """Simple data type."""


class AnyType(_SimpleType):
    """Bro/Zeek ``any`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.Any

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'any'

    def parse(self, data: typing.Any) -> typing.Any:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, str):
            data = data.encode('ascii')
        if data == self.unset_field:
            return None
        return data

    def tojson(self, data: typing.Any) -> typing.Any:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            The JSON representation of data.

        """
        try:
            json.dumps(data)
        except TypeError:
            return str(data)
        return data

    def toascii(self, data: typing.Any) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            The ASCII representation of data.

        """
        if data is None:
            return self.str_unset_field
        return str(data)


class BoolType(_SimpleType):
    """Bro/Zeek ``bool`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return bool

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'bool'

    def parse(self, data: typing.Union[typing.AnyStr, bool]) -> typing.Union[None, bool]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed boolean data. If ``data`` is *unset*, ``None`` will
            be returned.

        Raises:
            ZeekValueError: If ``data`` is NOT *unset* and NOT ``T`` (``True``)
                nor ``F`` (``False``) in Bro/Zeek script language.

        """
        if isinstance(data, bool):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        if data == b'T':
            return True
        if data == b'F':
            return False
        raise ZeekValueError('invalid bool value: %s' % data.decode('ascii'))

    def tojson(self, data: typing.Union[None, bool]) -> typing.Union[None, bool]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            The JSON serialisable boolean data.

        """
        return data

    def toascii(self, data: typing.Union[None, bool]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: ``T`` if ``True``, ``F`` if ``False``.

        """
        if data is None:
            return self.str_unset_field
        return 'T' if data else 'F'


class CountType(_SimpleType):
    """Bro/Zeek ``count`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.uint64

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'count'

    def parse(self, data: typing.Union[typing.AnyStr, typing.uint64]) -> typing.Union[None, typing.uint64]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, ctypes.c_uint64):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ctypes.c_uint64(int(data))

    def tojson(self, data: typing.Union[None, typing.uint64]) -> typing.Union[None, int]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return data
        return data.value

    def toascii(self, data: typing.Union[None, typing.uint64]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return str(data.value)


class IntType(_SimpleType):
    """Bro/Zeek ``int`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.int64

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'int'

    def parse(self, data: typing.Union[typing.AnyStr, typing.int64]) -> typing.Union[None, typing.int64]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, ctypes.c_int64):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ctypes.c_int64(int(data))

    def tojson(self, data: typing.Union[None, typing.int64]) -> typing.Union[None, int]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return data
        return data.value

    def toascii(self, data: typing.Union[None, typing.int64]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return str(data.value)


class DoubleType(_SimpleType):
    """Bro/Zeek ``double`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.Decimal

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'double'

    def parse(self, data: typing.Union[typing.AnyStr, typing.Decimal]) -> typing.Union[None, typing.Decimal]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, decimal.Decimal):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        with decimal.localcontext() as ctx:
            ctx.prec = 6
            value = decimal.Decimal(data.decode('ascii'))
        return value

    def tojson(self, data: typing.Union[None, typing.Decimal]) -> typing.Union[None, float]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            float: The JSON serialisable numeral data.

        """
        if data is None:
            return data
        return float(data)

    def toascii(self, data: typing.Union[None, typing.Decimal]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return decimal_toascii(data)


class TimeType(_SimpleType):
    """Bro/Zeek ``time`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.DateTime

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'time'

    def parse(self, data: typing.Union[typing.AnyStr, typing.DateTime]) -> typing.Union[None, typing.DateTime]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, datetime.datetime):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        with decimal.localcontext() as ctx:
            ctx.prec = 6
            value = decimal.Decimal(data.decode('ascii'))
        return datetime.datetime.fromtimestamp(value)

    def tojson(self, data: typing.Union[None, typing.DateTime]) -> typing.Union[None, float]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return data
        return data.timestamp()

    def toascii(self, data: typing.Union[None, typing.DateTime]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return float_toascii(data.timestamp())


class IntervalType(_SimpleType):
    """Bro/Zeek ``interval`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.TimeDelta

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'interval'

    def parse(self, data: typing.Union[typing.AnyStr, typing.TimeDelta]) -> typing.Union[None, typing.TimeDelta]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, datetime.timedelta):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        int_part, flt_part = data.split(b'.')
        return datetime.timedelta(seconds=int_part,
                                  microseconds=flt_part[:3],
                                  milliseconds=flt_part[3:])

    def tojson(self, data: typing.Union[None, typing.TimeDelta]) -> typing.Union[None, float]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return data
        return data.total_seconds()

    def toascii(self, data: typing.Union[None, typing.TimeDelta]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return float_toascii(data.total_seconds())


class StringType(_SimpleType):
    """Bro/Zeek ``string`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.ByteString

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'string'

    def parse(self, data: typing.Union[typing.AnyStr, memoryview, bytearray]) -> typing.Union[None, typing.ByteString]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed string data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, memoryview):
            return data.tobytes()
        if isinstance(data, str):
            return data.encode('ascii')

        if data == self.empty_field:
            return bytes()
        if data == self.unset_field:
            return None
        return bytes(str(data), encoding='ascii')

    def tojson(self, data: typing.Union[None, typing.ByteString]) -> typing.Union[None, str]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable string data encoded in ASCII.

        """
        return data.decode('ascii')

    def toascii(self, data: typing.Union[None, typing.ByteString]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII encoded string data.

        """
        if data is None:
            return self.str_unset_field
        if data:
            return data.decode('ascii')
        return self.str_empty_field


class AddrType(_SimpleType):
    """Bro/Zeek ``addr`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.IPAddress

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'addr'

    def parse(self, data: typing.Union[typing.AnyStr, typing.IPAddress]) -> typing.Union[None, typing.IPAddress]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed IP address. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return data
        if isinstance(data, str):
            return data.encode('ascii')

        if data == self.unset_field:
            return None
        return ipaddress.ip_address(data.decode('ascii'))

    def tojson(self, data: typing.Union[None, typing.IPAddress]) -> typing.Union[None, str]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable IP address string.

        """
        if data is None:
            return data
        return str(data)

    def toascii(self, data: typing.Union[None, typing.IPAddress]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the IP address.

        """
        if data is None:
            return self.str_unset_field
        return str(data)


class PortType(Type):
    """Bro/Zeek ``port`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.uint16

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'port'

    def parse(self, data: typing.Union[typing.AnyStr, typing.uint16]) -> typing.Union[None, typing.uint16]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed port number. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, ctypes.c_uint16):
            return data
        if isinstance(data, str):
            return data.encode('ascii')

        if data == self.unset_field:
            return None
        return ctypes.c_uint16(int(data))

    def tojson(self, data: typing.Union[None, typing.uint16]) -> typing.Union[None, int]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable port number string.

        """
        if data is None:
            return data
        return data.value

    def toascii(self, data: typing.Union[None, typing.uint16]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the port number.

        """
        if data is None:
            return self.str_unset_field
        return str(data.value)


class SubnetType(_SimpleType):
    """Bro/Zeek ``subnet`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.IPNetwork

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'port'

    def parse(self, data: typing.Union[typing.AnyStr, typing.IPNetwork]) -> typing.Union[None, typing.IPNetwork]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed IP network. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ipaddress.ip_network(data.decode('ascii'))

    def tojson(self, data: typing.Union[None, typing.IPNetwork]) -> typing.Union[None, str]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable IP network string.

        """
        if data is None:
            return data
        return str(data)

    def toascii(self, data: typing.Union[None, typing.IPNetwork]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the IP network.

        """
        if data is None:
            return self.str_unset_field
        return str(data)


class EnumType(_SimpleType):
    """Bro/Zeek ``enum`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields
        enum_namespaces (:obj:`Dict[str, Enum]`): global namespace for ``enum`` data type

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.Enum

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'enum'

    def __init__(self, empty_field=None, unset_field=None, set_separator=None,
                 namespaces: typing.Optional[typing.List[str]] = None, bare: bool = False,
                 enum_hook: typing.Optional[typing.Dict[str, typing.Enum]] = None):
        """Initialisation.

        Args:
            empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
            set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields
            namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            bare (:obj:`bool`, optional): if ``True``, do not load ``zeek`` namespace by default
            enum_hook (:obj:`Dict[str, Enum]`, optional): additional enum to be included in the namespace

        """
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        if namespaces is None:
            namespaces = list()
        self.enum_namespaces = enum_generator(*namespaces, bare=bare)
        if enum_hook is not None:
            self.enum_namespaces.update(enum_hook)

    def __repr__(self) -> str:
        return ('%s(empty_field=%s, unset_field=%s, '
                'set_separator=%s, enum_namespaces=%s)') % (type(self).__name__,
                                                            self.empty_field, self.unset_field,
                                                            self.set_separator, self.enum_namespaces)

    def parse(self, data: typing.Union[typing.AnyStr, typing.Enum]) -> typing.Union[None, typing.Enum]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed enum data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, enum.Enum):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        data_str = data.decode('ascii')
        item = self.enum_namespaces.get()
        if item is None:
            warnings.warn('unrecognised enum value: %s' % data_str, ZeekValueWarning)
            return enum.IntFlag('<unknown>', [(data_str, enum.auto())])[data_str]
        return item

    def tojson(self, data: typing.Union[None, typing.Enum]) -> typing.Union[None, str]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable enum data.

        """
        if data is None:
            return data
        return data.name

    def toascii(self, data: typing.Union[None, typing.Enum]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the enum data.

        """
        if data is None:
            return self.str_unset_field
        return data.name


_data = typing.TypeVar('data', AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                       IntType, PortType, StringType, SubnetType, TimeType)


class _GenericType(Type):  # pylint: disable=abstract-method
    """Generic data type."""


class SetType(_GenericType, typing.Generic[_data]):
    """Bro/Zeek ``set`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields
        element_type (:obj:`Type` instance), data type of container's elements

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.Set[_data]

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'set'

    def __init__(self, empty_field=None, unset_field=None, set_separator=None,
                 element_type: _SimpleType = None):
        """Initialisation.

        Args:
            empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
            set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields
            namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            element_type (:obj:`Type` instance or class, required), data type of container's elements

        Raises:
            ZeekTypeError: if ``element_type`` is not supplied
            ZeekValueError: if ``element_type`` is not a valid Bro/Zeek data type

        """
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        if element_type is None:
            raise ZeekTypeError("__init__() missing 1 required positional argument: 'element_type'")
        if not isinstance(element_type, _SimpleType):
            if isinstance(element_type, type) and issubclass(element_type, _SimpleType):
                element_type = element_type(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)  # pylint: disable=line-too-long
            else:
                raise ZeekValueError('invalid element type: %r' % type(element_type).__name__)
        self.element_type = element_type

    def __repr__(self) -> str:
        return ('%s(empty_field=%s, unset_field=%s, '
                'set_separator=%s, element_type=%s)') % (type(self).__name__,
                                                         self.empty_field, self.unset_field,
                                                         self.set_separator, self.element_type)

    def parse(self, data: typing.Union[typing.AnyStr, typing.Set[_data]]) -> typing.Union[None, typing.Set[_data]]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed set data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, set):
            return set(self.element_type(element) for element in data)
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        if data == self.empty_field:
            return set()
        return set(self.element_type(element) for element in data.split(self.set_separator))

    def tojson(self, data: typing.Union[None, typing.Set[_data]]) -> typing.Union[None, typing.List[_data]]:
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            list: The JSON serialisable set data.

        """
        if data is None:
            return None
        return list(self.element_type.tojson(element) for element in data)

    def toascii(self, data: typing.Union[None, typing.Set[_data]]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the set data.

        """
        if data is None:
            return self.str_unset_field
        if not data:
            return self.str_empty_field
        return self.set_separator.join(self.element_type.toascii(element) for element in data)


class VectorType(_GenericType, typing.Generic[_data]):
    """Bro/Zeek ``vector`` data type.

    Attributes:
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields
        element_type (:obj:`Type` instance), data type of container's elements

    """

    @property
    def python_type(self) -> typing.Type:
        """type: corresponding Python type annotation."""
        return typing.List[_data]

    @property
    def zeek_type(self) -> str:
        """str: corresponding Zeek type name."""
        return 'vector'

    def __init__(self, empty_field=None, unset_field=None, set_separator=None,
                 element_type: _SimpleType = None):
        """Initialisation.

        Args:
            empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
            set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields
            namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            element_type (:obj:`Type` instance or class, required), data type of container's elements

        Raises:
            ZeekTypeError: if ``element_type`` is not supplied
            ZeekValueError: if ``element_type`` is not a valid Bro/Zeek data type

        """
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        if element_type is None:
            raise ZeekTypeError('__init__() missing 1 required positional argument: %r' % element_type)
        if not isinstance(element_type, _SimpleType):
            if isinstance(element_type, type) and issubclass(element_type, _SimpleType):
                element_type = element_type(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)  # pylint: disable=line-too-long
            else:
                raise ZeekValueError('invalid element type: %r' % type(element_type).__name__)
        self.element_type = element_type

    def __repr__(self) -> str:
        return ('%s(empty_field=%s, unset_field=%s, '
                'set_separator=%s, element_type=%s)') % (type(self).__name__,
                                                         self.empty_field, self.unset_field,
                                                         self.set_separator, self.element_type)

    def parse(self, data: typing.Union[typing.AnyStr, typing.List[_data]]) -> typing.Union[None, typing.List[_data]]:
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed list data. If ``data`` is *unset*, ``None`` will
            be returned.

        """
        if isinstance(data, list):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        if data == self.empty_field:
            return list()
        return list(self.element_type(element) for element in data.split(self.set_separator))

    def tojson(self, data: typing.Union[None, typing.List[_data]]) -> typing.Union[None, typing.List[_data]]:  # pylint: disable=line-too-long
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            list: The JSON serialisable list data.

        """
        if data is None:
            return None
        return list(self.element_type.tojson(element) for element in data)

    def toascii(self, data: typing.Union[None, typing.List[_data]]) -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the list data.

        """
        if data is None:
            return self.str_unset_field
        if not data:
            return self.str_empty_field
        return self.set_separator.join(self.element_type.toascii(element) for element in data)
