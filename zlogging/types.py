# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports,unsubscriptable-object
"""Bro/Zeek data types."""

import abc
import ctypes
import datetime
import decimal
import ipaddress
import json
import warnings
from typing import TYPE_CHECKING, Any, Generic, List, Set, TypeVar, Union, cast, overload

from typing_extensions import TypedDict
from typing_inspect import get_args, is_union_type

from zlogging._aux import decimal_toascii, expand_typing, float_toascii
from zlogging._compat import enum
from zlogging._exc import (BroDeprecationWarning, ZeekNotImplemented, ZeekTypeError, ZeekValueError,
                   ZeekValueWarning)
from zlogging.enum import globals as enum_generator

_T = TypeVar("_T")
_S = TypeVar('_S', bound='_SimpleType')
_Str = TypeVar('_Str', str, bytes)
_Bool = TypeVar('_Bool', 'Literal[True]', 'Literal[False]')
if TYPE_CHECKING:
    from collections import OrderedDict
    from ctypes import c_int64 as int64
    from ctypes import c_uint16 as uint16
    from ctypes import c_uint64 as uint64
    from datetime import datetime as DateTimeType
    from datetime import timedelta as TimeDeltaType
    from decimal import Decimal
    from enum import Enum as _Enum
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
    from typing import Dict, NoReturn, Optional, Tuple, Type

    from aenum import Enum as _AEnum
    from typing_extensions import Literal

    AnyStr = Union[str, bytes]
    ByteString = Union[bytes, bytearray, memoryview]
    IPAddress = Union[IPv4Address, IPv6Address]
    IPNetwork = Union[IPv4Network, IPv6Network]

    class Enum(_Enum, _AEnum):  # pylint: disable=duplicate-bases
        def __init__(self, value: str, names: Union[str, List[str], List[Tuple[str, Any]], Dict[str, Any]], *,  # pylint: disable=unused-argument,super-init-not-called
                     module: Optional[str] = None, qualname: Optional[str] = None,  # pylint: disable=unused-argument
                     type: Optional[type] = None, start: Optional[int] = 1): ...  # pylint: disable=unused-argument,redefined-builtin
        def __getitem__(self: '_T', name: str) -> '_T': ...  # pylint: disable=multiple-statements

__all__ = [
    'AddrType', 'BoolType', 'CountType', 'DoubleType', 'EnumType',
    'IntervalType', 'IntType', 'PortType', 'RecordType', 'SetType',
    'StringType', 'SubnetType', 'TimeType', 'VectorType',
]


class BaseType(metaclass=abc.ABCMeta):
    """Base Bro/Zeek data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    @abc.abstractmethod
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""

    @property
    @abc.abstractmethod
    def zeek_type(self) -> str:
        """str: Corresponding Zeek type name."""

    @property
    def bro_type(self) -> str:
        """str: Corresponding Bro type name."""
        warnings.warn("Use of 'bro_type' is deprecated. "
                      "Please use 'zeek_type' instead.", BroDeprecationWarning)
        return self.zeek_type

    def __init__(self,   # pylint: disable=unused-argument,keyword-arg-before-vararg
                 empty_field: 'Optional[AnyStr]' = None, unset_field: 'Optional[AnyStr]' = None,
                 set_separator: 'Optional[AnyStr]' = None, *args: 'Any', **kwargs: 'Any') -> None:
        if empty_field is None:
            self.empty_field = b'(empty)'
            self.str_empty_field = '(empty)'
        elif isinstance(empty_field, str):
            self.empty_field = empty_field.encode('ascii')
            self.str_empty_field = empty_field
        else:
            self.empty_field = empty_field
            self.str_empty_field = empty_field.decode('ascii')

        if unset_field is None:
            self.unset_field = b'-'
            self.str_unset_field = '-'
        elif isinstance(unset_field, str):
            self.unset_field = unset_field.encode('ascii')
            self.str_unset_field = unset_field
        else:
            self.unset_field = unset_field
            self.str_unset_field = unset_field.decode('ascii')

        if set_separator is None:
            self.set_separator = b','
            self.str_set_separator = ','
        elif isinstance(set_separator, str):
            self.set_separator = set_separator.encode('ascii')
            self.str_set_separator = set_separator
        else:
            self.set_separator = set_separator
            self.str_set_separator = set_separator.decode('ascii')

        self._name = type(self).__name__

    def __call__(self, data: 'Any') -> 'Any':
        """Parse ``data`` from string.

        This is a proxy method which calls to :meth:`~zlogging.types.BaseType.parse`
        of the type implementation.

        """
        if data is None:
            return data
        return self.parse(data)

    def __str__(self) -> str:
        """Returns the corresponding Zeek type name."""
        return self.zeek_type

    def __repr__(self) -> str:
        return (f'{self._name}(empty_field={self.str_empty_field}, '
                f'unset_field={self.str_unset_field}, set_separator={self.str_set_separator})')

    @abc.abstractmethod
    def parse(self, data: 'Any') -> 'Any':
        """Parse ``data`` from string."""

    @abc.abstractmethod
    def tojson(self, data: 'Any') -> 'Any':
        """Serialize ``data`` as JSON log format."""

    @abc.abstractmethod
    def toascii(self, data: 'Any') -> str:
        """Serialize ``data`` as ASCII log format."""


class _SimpleType(BaseType):  # pylint: disable=abstract-method
    """Simple data type.

    In Bro/Zeek script language, such simple type includes ``bool``, ``count``,
    ``int``, ``double``, ``time``, ``interval``, ``string``, ``addr``,
    ``port``, ``subnet`` and ``enum``.

    To support arbitrary typing as required in :class:`~zlogging.loader.JSONParser`,
    ``any``, the arbitrary date type is also included.

    """


class AnyType(_SimpleType):
    """Bro/Zeek ``any`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    Note:
        The :class:`~zlogging.types.AnyType` is only used for arbitrary typing
        as required in :class:`~zlogging.loader.JSONParser`. It is **NOT** a
        valid type of Bro/Zeek logging framework.

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        return Any

    @property
    def zeek_type(self) -> 'Literal["any"]':
        """str: Corresponding Zeek type name."""
        return 'any'

    def parse(self, data: '_T') -> 'Optional[_T]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed data. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        r_data = data.encode('ascii') if isinstance(data, str) else data
        if r_data == self.unset_field:
            return None
        return data

    def tojson(self, data: 'Any') -> 'Any':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            The JSON representation of data.

        Notes:
            If the data is not JSON serialisable, i.e. :func:`json.dumps`
            raises :exc:`TypeError`, the method will return a :obj:`dict`
            object with ``data`` representing :obj:`str` sanitised raw data
            and ``error`` representing the error message.

        """
        try:
            json.dumps(data)
        except TypeError as error:
            return {
                'data': str(data),
                'error': str(error),
            }
        return data

    def toascii(self, data: 'Any') -> str:
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

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self)-> 'Type[bool]':
        """Any: Corresponding Python type annotation."""
        return bool

    @property
    def zeek_type(self) -> 'Literal["bool"]':
        """str: Corresponding Zeek type name."""
        return 'bool'

    @overload
    def parse(self, data: 'Literal["T", b"T"]') -> 'Literal[True]': ...
    @overload
    def parse(self, data: 'Literal["F", b"F"]') -> 'Literal[False]': ...
    @overload
    def parse(self, data: '_Str') -> 'Optional[bool]': ...
    def parse(self, data: 'Union[AnyStr, bool]') -> 'Optional[bool]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed boolean data. If ``data`` is *unset*, :data:`None` will
            be returned.

        Raises:
            ZeekValueError: If ``data`` is NOT *unset* and NOT ``T`` (:data:`True`)
                nor ``F`` (:data:`False`) in Bro/Zeek script language.

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

    @overload
    def tojson(self, data: _Bool) -> _Bool: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[bool]') -> 'Optional[bool]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            The JSON serialisable boolean data.

        """
        return data

    @overload
    def toascii(self, data: 'Literal[True]') -> 'Literal["T"]': ...
    @overload
    def toascii(self, data: 'Literal[False]') -> 'Literal["F"]': ...
    @overload
    def toascii(self, data: None) -> str: ...
    def toascii(self, data: 'Optional[bool]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: ``T`` if :data:`True`, ``F`` if :data:`False`.

        """
        if data is None:
            return self.str_unset_field
        return 'T' if data else 'F'


class CountType(_SimpleType):
    """Bro/Zeek ``count`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Type[uint64]':
        """Any: Corresponding Python type annotation."""
        return ctypes.c_uint64

    @property
    def zeek_type(self) -> 'Literal["count"]':
        """str: Corresponding Zeek type name."""
        return 'count'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[uint64]': ...
    @overload
    def parse(self, data: 'uint64') -> 'uint64': ...
    def parse(self, data: 'Union[AnyStr, uint64]') -> 'Optional[uint64]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, ctypes.c_uint64):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ctypes.c_uint64(int(data))

    @overload
    def tojson(self, data: 'uint64') -> int: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[uint64]') -> 'Optional[int]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return None
        return data.value

    def toascii(self, data: 'Optional[uint64]') -> str:
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

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Type[int64]':
        """Any: Corresponding Python type annotation."""
        return ctypes.c_int64

    @property
    def zeek_type(self) -> 'Literal["int"]':
        """str: Corresponding Zeek type name."""
        return 'int'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[int64]': ...
    @overload
    def parse(self, data: 'int64') -> 'int64': ...
    def parse(self, data: 'Union[AnyStr, int64]') -> 'Optional[int64]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, ctypes.c_int64):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ctypes.c_int64(int(data))

    @overload
    def tojson(self, data: 'int64') -> int: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[int64]') -> 'Optional[int]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return None
        return data.value

    def toascii(self, data: 'Optional[int64]') -> str:
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

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Type[Decimal]':
        """Any: Corresponding Python type annotation."""
        return decimal.Decimal

    @property
    def zeek_type(self) -> 'Literal["double"]':
        """str: Corresponding Zeek type name."""
        return 'double'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[Decimal]': ...
    @overload
    def parse(self, data: 'Decimal') -> 'Decimal': ...
    def parse(self, data: 'Union[AnyStr, Decimal]') -> 'Optional[Decimal]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, :data:`None` will
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

    @overload
    def tojson(self, data: 'Decimal') -> float: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[Decimal]') -> 'Optional[float]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            float: The JSON serialisable numeral data.

        """
        if data is None:
            return None
        return float(data)

    def toascii(self, data: 'Optional[Decimal]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return decimal_toascii(data, self.str_unset_field)


class TimeType(_SimpleType):
    """Bro/Zeek ``time`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Type[DateTimeType]':
        """Any: Corresponding Python type annotation."""
        return datetime.datetime

    @property
    def zeek_type(self) -> 'Literal["time"]':
        """str: Corresponding Zeek type name."""
        return 'time'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[DateTimeType]': ...
    @overload
    def parse(self, data: 'DateTimeType') -> 'DateTimeType': ...
    def parse(self, data: 'Union[AnyStr, DateTimeType]') -> 'Optional[DateTimeType]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, :data:`None` will
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
        return datetime.datetime.fromtimestamp(float(value))

    @overload
    def tojson(self, data: 'DateTimeType') -> float: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[DateTimeType]') -> 'Optional[float]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            float: The JSON serialisable numeral data.

        """
        if data is None:
            return None
        return data.timestamp()

    def toascii(self, data: 'Optional[DateTimeType]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return float_toascii(data.timestamp(), self.str_unset_field)


class IntervalType(_SimpleType):
    """Bro/Zeek ``interval`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Type[TimeDeltaType]':
        """Any: Corresponding Python type annotation."""
        return datetime.timedelta

    @property
    def zeek_type(self) -> 'Literal["interval"]':
        """str: Corresponding Zeek type name."""
        return 'interval'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[TimeDeltaType]': ...
    @overload
    def parse(self, data: 'TimeDeltaType') -> 'TimeDeltaType': ...
    def parse(self, data: 'Union[AnyStr, TimeDeltaType]') -> 'Optional[TimeDeltaType]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed numeral data. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, datetime.timedelta):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        int_part, flt_part = data.split(b'.')
        return datetime.timedelta(seconds=int(int_part),
                                  microseconds=int(flt_part[:3]),
                                  milliseconds=int(flt_part[3:]))

    @overload
    def tojson(self, data: 'TimeDeltaType') -> float: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[TimeDeltaType]') -> 'Optional[float]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable numeral data.

        """
        if data is None:
            return None
        return data.total_seconds()

    def toascii(self, data: 'Optional[TimeDeltaType]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of numeral data.

        """
        if data is None:
            return self.str_unset_field
        return float_toascii(data.total_seconds(), self.str_unset_field)


class StringType(_SimpleType):
    """Bro/Zeek ``string`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        return Union[bytes, memoryview, bytearray]

    @property
    def zeek_type(self) -> 'Literal["string"]':
        """str: Corresponding Zeek type name."""
        return 'string'

    def parse(self, data: 'Union[AnyStr, ByteString]') -> 'Optional[bytes]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed string data. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, memoryview):
            data = data.tobytes()
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.empty_field:
            return b''
        if data == self.unset_field:
            return None
        return data

    @overload
    def tojson(self, data: 'ByteString') -> str: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[ByteString]') -> 'Optional[str]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable string data encoded in ASCII.

        """
        if data is None:
            return None

        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, memoryview):
            data = data.tobytes()
        return data.decode('ascii')

    def toascii(self, data: 'Optional[ByteString]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII encoded string data.

        """
        if data is None:
            return self.str_unset_field

        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, memoryview):
            data = data.tobytes()

        if data:
            return data.decode('ascii')
        return self.str_empty_field


class AddrType(_SimpleType):
    """Bro/Zeek ``addr`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        return Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

    @property
    def zeek_type(self) -> str:
        """str: Corresponding Zeek type name."""
        return 'addr'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[IPAddress]': ...
    @overload
    def parse(self, data: 'IPAddress') -> 'IPAddress': ...
    def parse(self, data: 'Union[AnyStr, IPAddress]') -> 'Optional[IPAddress]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed IP address. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ipaddress.ip_address(data.decode('ascii'))

    @overload
    def tojson(self, data: 'IPAddress') -> str: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[IPAddress]') -> 'Optional[str]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable IP address string.

        """
        if data is None:
            return None
        return str(data)

    def toascii(self, data: 'Optional[IPAddress]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the IP address.

        """
        if data is None:
            return self.str_unset_field
        return str(data)


class PortType(_SimpleType):
    """Bro/Zeek ``port`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Type[uint16]':
        """Any: Corresponding Python type annotation."""
        return ctypes.c_uint16

    @property
    def zeek_type(self) -> 'Literal["port"]':
        """str: Corresponding Zeek type name."""
        return 'port'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[uint16]': ...
    @overload
    def parse(self, data: 'uint16') -> 'uint16': ...
    def parse(self, data: 'Union[AnyStr, uint16]') -> 'Optional[uint16]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed port number. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, ctypes.c_uint16):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ctypes.c_uint16(int(data))

    @overload
    def tojson(self, data: 'uint16') -> int: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[uint16]') -> 'Optional[int]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            int: The JSON serialisable port number string.

        """
        if data is None:
            return None
        return data.value

    def toascii(self, data: 'Optional[uint16]') -> str:
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

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        return Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

    @property
    def zeek_type(self) -> str:
        """str: Corresponding Zeek type name."""
        return 'port'

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[IPNetwork]': ...
    @overload
    def parse(self, data: 'IPNetwork') -> 'IPNetwork': ...
    def parse(self, data: 'Union[AnyStr, IPNetwork]') -> 'Optional[IPNetwork]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed IP network. If ``data`` is *unset*, :data:`None` will
            be returned.

        """
        if isinstance(data, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        return ipaddress.ip_network(data.decode('ascii'))

    @overload
    def tojson(self, data: 'IPNetwork') -> str: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[IPNetwork]') -> 'Optional[str]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable IP network string.

        """
        if data is None:
            return None
        return str(data)

    def toascii(self, data: 'Optional[IPNetwork]') -> str:
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

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        namespaces (:obj:`List[str]`, optional): Namespaces to be loaded.
        bare (:obj:`bool`, optional): If :data:`True`, do not load ``zeek`` namespace by default.
        enum_hook (:obj:`dict` mapping of :obj:`str` and :obj:`enum.Enum`, optional):
            Additional enum to be included in the namespace.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.
        enum_namespaces (:obj:`dict` mapping :obj:`str` and :obj:`enum.Enum`):
            Global namespace for ``enum`` data type.

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        return enum.Enum

    @property
    def zeek_type(self) -> str:
        """str: Corresponding Zeek type name."""
        return 'enum'

    def __init__(self,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                 empty_field: 'Optional[AnyStr]' = None,
                 unset_field: 'Optional[AnyStr]' = None,
                 set_separator: 'Optional[AnyStr]' = None,
                 namespaces: 'Optional[List[str]]' = None,
                 bare: bool = False,
                 enum_hook: 'Optional[Dict[str, Enum]]' = None,
                 *args: 'Any', **kwargs: 'Any') -> None:
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        if namespaces is None:
            namespaces = list()
        self.enum_namespaces = enum_generator(*namespaces, bare=bare)
        if enum_hook is not None:
            self.enum_namespaces.update(enum_hook)

    def __repr__(self) -> str:
        return (f'{self._name}(empty_field={self.str_empty_field}, unset_field={self.str_unset_field}, '
                f'set_separator={self.str_set_separator}, enum_namespaces={self.enum_namespaces})')

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[Enum]': ...  # type: ignore[misc]
    @overload
    def parse(self, data: 'Enum') -> 'Enum': ...
    def parse(self, data: 'Union[AnyStr, Enum]') -> 'Optional[Enum]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed enum data. If ``data`` is *unset*, :data:`None` will
            be returned.

        Warns:
            ZeekValueWarning: If ``date`` is not defined in the enum namespace.

        """
        if isinstance(data, enum.Enum):
            return data
        if isinstance(data, str):
            data = data.encode('ascii')

        if data == self.unset_field:
            return None
        data_str = data.decode('ascii')

        item = self.enum_namespaces.get(data_str)
        if item is None:
            warnings.warn('unrecognised enum value: %s' % data_str, ZeekValueWarning)
            unknown = cast('Type[Enum]', enum.IntFlag)('<unknown>', {
                data_str: enum.auto(),
            }, module='zlogging.enum', qualname='zlogging.enum.<unknown>')
            item = unknown[data_str]
        return item  # type: ignore[return-value]

    @overload
    def tojson(self, data: 'Enum') -> str: ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[Enum]') -> 'Optional[str]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            str: The JSON serialisable enum data.

        """
        if data is None:
            return None
        return data.name

    def toascii(self, data: 'Optional[Enum]') -> str:
        """Serialize ``data`` as ASCII log format.

        Args:
            data: raw data

        Returns:
            str: The ASCII representation of the enum data.

        """
        if data is None:
            return self.str_unset_field
        return data.name


class _GenericType(BaseType):  # pylint: disable=abstract-method
    """Generic data type.

    In Bro/Zeek script language, such generic type includes ``set`` and
    ``vector``, which are also known as *container* types.

    """


class SetType(_GenericType, Generic[_S]):
    """Bro/Zeek ``set`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        element_type (:class:`~zlogging.types.BaseType` instance): Data type of container's elements.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.
        element_type (:class:`~zlogging.types.BaseType` instance): Data type of container's elements.

    Raises:
        :exc:`ZeekTypeError`: If ``element_type`` is not supplied.
        :exc:`ZeekValueError`: If ``element_type`` is not a valid Bro/Zeek data type.

    Example:
        As a *generic* data type, the class supports the typing proxy as introduced
        `PEP 484`_::

            >>> SetType[StringType]

        which is the same **at runtime** as following::

            >>> SetType(element_type=StringType())

    Note:
        A valid ``element_type`` should be a *simple* data type, i.e. a subclass
        of :class:`~zlogging.types._SimpleType`.

    .. _PEP 484:
        https://www.python.org/dev/peps/pep-0484/

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        python_type = self.element_type.python_type
        is_union = is_union_type(python_type)
        if is_union:
            args = get_args(python_type)  # type: Tuple[Any]
            sets = tuple(Set[arg] for arg in args)  # type: ignore[valid-type]
            return Union[sets]
        return Set[python_type]  # type: ignore[valid-type]

    @property
    def zeek_type(self) -> str:
        """str: Corresponding Zeek type name."""
        return 'set[%s]' % self.element_type.zeek_type

    def __init__(self,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                 empty_field: 'Optional[AnyStr]' = None,
                 unset_field: 'Optional[AnyStr]' = None,
                 set_separator: 'Optional[AnyStr]' = None,
                 element_type: 'Optional[Union[_S, Type[_S]]]' = None,
                 *args: 'Any', **kwargs: 'Any') -> None:
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        if element_type is None:
            raise ZeekTypeError("__init__() missing 1 required positional argument: 'element_type'")
        if not isinstance(element_type, _SimpleType):
            if isinstance(element_type, type) and issubclass(element_type, _SimpleType):
                element_type = element_type(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)  # pylint: disable=line-too-long
            else:
                raise ZeekValueError('invalid element type: %s' % type(element_type).__name__)
        self.element_type = element_type

    def __repr__(self) -> str:
        return (f'{self._name}(empty_field={self.str_empty_field}, unset_field={self.str_unset_field}, '
                f'set_separator={self.str_set_separator}, element_type={self.element_type})')

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[Set[_S]]': ...
    @overload
    def parse(self, data: 'Set[_S]') -> 'Set[_S]': ...
    def parse(self, data: 'Union[AnyStr, Set[_S]]') -> 'Optional[Set[_S]]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed set data. If ``data`` is *unset*, :data:`None` will
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

    @overload
    def tojson(self, data: 'Set[_S]') -> 'List[Optional[_T]]': ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[Set[_S]]') -> 'Optional[List[Optional[_T]]]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            list: The JSON serialisable set data.

        """
        if data is None:
            return None
        return list(self.element_type.tojson(element) for element in data)

    def toascii(self, data: 'Optional[Set[_S]]') -> str:
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
        return self.str_set_separator.join(self.element_type.toascii(element) for element in data)


class VectorType(_GenericType, Generic[_S]):
    """Bro/Zeek ``vector`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        element_type (:class:`~zlogging.types.BaseType` instance): Data type of container's elements.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.
        element_type (:class:`~zlogging.types.BaseType` instance): Data type of container's elements.

    Raises:
        :exc:`ZeekTypeError`: If ``element_type`` is not supplied.
        :exc:`ZeekValueError`: If ``element_type`` is not a valid Bro/Zeek data type.

    Example:
        As a *generic* data type, the class supports the typing proxy as introduced
        `PEP 484`_::

            >>> VectorType[StringType]

        which is the same **at runtime** as following::

            >>> VectorType(element_type=StringType())

    Note:
        A valid ``element_type`` should be a *simple* data type, i.e. a subclass
        of :class:`~zlogging.types._SimpleType`.

    .. _PEP 484:
        https://www.python.org/dev/peps/pep-0484/

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        python_type = self.element_type.python_type
        is_union = is_union_type(python_type)
        if is_union:
            args = get_args(python_type)  # type: Tuple[Any]
            name = tuple(List[arg] for arg in args)  # type: ignore[valid-type]
            return Union[name]
        return List[python_type]  # type: ignore[valid-type]

    @property
    def zeek_type(self) -> str:
        """str: Corresponding Zeek type name."""
        return 'vector[%s]' % self.element_type.zeek_type

    def __init__(self,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                 empty_field: 'Optional[AnyStr]' = None,
                 unset_field: 'Optional[AnyStr]' = None,
                 set_separator: 'Optional[AnyStr]' = None,
                 element_type: 'Optional[Union[_S, Type[_S]]]' = None,
                 *args: 'Any', **kwargs: 'Any'):
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        if element_type is None:
            raise ZeekTypeError('__init__() missing 1 required positional argument: %r' % element_type)
        if not isinstance(element_type, _SimpleType):
            if isinstance(element_type, type) and issubclass(element_type, _SimpleType):
                element_type = element_type(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)  # pylint: disable=line-too-long
            else:
                raise ZeekValueError('invalid element type: %s' % type(element_type).__name__)
        self.element_type = element_type

    def __repr__(self) -> str:
        return (f'{self._name}(empty_field={self.str_empty_field}, unset_field={self.str_unset_field}, '
                f'set_separator={self.str_set_separator}, element_type={self.element_type})')

    @overload
    def parse(self, data: 'AnyStr') -> 'Optional[List[_S]]': ...
    @overload
    def parse(self, data: 'List[_S]') -> 'List[_S]': ...
    def parse(self, data: 'Union[AnyStr, List[_S]]') -> 'Optional[List[_S]]':
        """Parse ``data`` from string.

        Args:
            data: raw data

        Returns:
            The parsed list data. If ``data`` is *unset*, :data:`None` will
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

    @overload
    def tojson(self, data: 'List[_S]') -> 'List[Optional[_T]]': ...
    @overload
    def tojson(self, data: None) -> None: ...
    def tojson(self, data: 'Optional[List[_S]]') -> 'Optional[List[Optional[_T]]]':
        """Serialize ``data`` as JSON log format.

        Args:
            data: raw data

        Returns:
            list: The JSON serialisable list data.

        """
        if data is None:
            return None
        return list(self.element_type.tojson(element) for element in data)

    def toascii(self, data: 'Optional[List[_S]]') -> str:
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
        return self.str_set_separator.join(self.element_type.toascii(element) for element in data)


class _VariadicType(BaseType):  # pylint: disable=abstract-method
    """Variadic data type.

    In Bro/Zeek script language, such variadic type refers to ``record``, which
    is also a *container* type.

    """

    element_mapping: 'OrderedDict[str, Union[_SimpleType, _GenericType]]'

    def parse(self, data: 'Any') -> 'NoReturn':
        """Not supported for a variadic data type.

        Args:
            data: data to process

        Raises:
            :exc:`ZeekNotImplemented`: If try to call such method.

        """
        raise ZeekNotImplemented

    def tojson(self, data: 'Any') -> 'NoReturn':
        """Not supported for a variadic data type.

        Args:
            data: data to process

        Raises:
            :exc:`ZeekNotImplemented`: If try to call such method.

        """
        raise ZeekNotImplemented

    def toascii(self, data: 'Any') -> 'NoReturn':
        """Not supported for a variadic data type.

        Args:
            data: data to process

        Raises:
            :exc:`ZeekNotImplemented`: If try to call such method.

        """
        raise ZeekNotImplemented


class RecordType(_VariadicType):
    """Bro/Zeek ``record`` data type.

    Args:
        empty_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for empty field.
        unset_field (:obj:`bytes` or :obj:`str`, optional): Placeholder for unset field.
        set_separator (:obj:`bytes` or :obj:`str`, optional): Separator for ``set``/``vector`` fields.
        *args: Variable length argument list.
        **kwargs: element_mapping (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` instance):
            Data type of container's elements.

    Attributes:
        empty_field (bytes): Placeholder for empty field.
        unset_field (bytes): Placeholder for unset field.
        set_separator (bytes): Separator for ``set``/``vector`` fields.
        element_mapping (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` instance):
            Data type of container's elements.

    Raises:
        :exc:`ZeekTypeError`: If ``element_mapping`` is not supplied.
        :exc:`ZeekValueError`: If ``element_mapping`` is not a valid Bro/Zeek
            data type; or in case of inconsistency from ``empty_field``,
            ``unset_field`` and ``set_separator`` of each field.

    Note:
        A valid ``element_mapping`` should be a *simple* or *generic* data type,
        i.e. a subclass of :class:`~zlogging.types._SimpleType` or
        :class:`~zlogging.types._GenericType`.

    See Also:
        See :func:`~zlogging._aux_expand_typing` for more information about
        processing the fields.

    """

    @property
    def python_type(self) -> 'Any':
        """Any: Corresponding Python type annotation."""
        dict_entries = {
            field: element_type.python_type
            for field, element_type in self.element_mapping.items()
        }  # type: Dict[str, Any]
        return TypedDict('record', dict_entries)  # type: ignore[operator]

    @property
    def zeek_type(self) -> 'Literal["record"]':
        """str: Corresponding Zeek type name."""
        return 'record'

    def __init__(self,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                 empty_field: 'Optional[AnyStr]' = None,
                 unset_field: 'Optional[AnyStr]' = None,
                 set_separator: 'Optional[AnyStr]' = None,
                 *args: 'Any', **element_mapping: 'Union[Type[_SimpleType], _SimpleType, _GenericType]') -> None:
        super().__init__(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)

        expanded = expand_typing(self, ZeekValueError)
        if self.empty_field != expanded['empty_field']:
            raise ZeekValueError("inconsistent value of 'empty_field': %r and %r" % (self.empty_field, expanded['empty_field']))  # pylint: disable=line-too-long
        if self.unset_field != expanded['unset_field']:
            raise ZeekValueError("inconsistent value of 'unset_field': %r and %r" % (self.unset_field, expanded['unset_field']))  # pylint: disable=line-too-long
        if self.set_separator != expanded['set_separator']:
            raise ZeekValueError("inconsistent value of 'set_separator': %r and %r" % (self.set_separator, expanded['set_separator']))  # pylint: disable=line-too-long

        fields = expanded['fields']
        for field, expanded_type in fields.items():
            if isinstance(expanded_type, (_SimpleType, _GenericType)):
                continue
            raise ZeekValueError('invalid element type of field %r: %s' % (field, type(expanded_type).__name__))
        for field, element_type in element_mapping.items():
            if not isinstance(element_type, (_SimpleType, _GenericType)):
                if isinstance(element_type, type) and issubclass(element_type, _SimpleType):  # type: ignore[unreachable] # pylint: disable=line-too-long
                    element_type = element_type(empty_field=empty_field, unset_field=unset_field, set_separator=set_separator)  # pylint: disable=line-too-long
                else:
                    raise ZeekValueError('invalid element type of field %r: %s' % (field, type(element_type).__name__))
            fields[field] = element_type
        self.element_mapping = fields

    def __repr__(self) -> str:
        return (f'{self._name}(empty_field={self.str_empty_field}, unset_field={self.str_unset_field}, '
                f'set_separator={self.str_set_separator}, element_mapping={self.element_mapping})')
