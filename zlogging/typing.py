# -*- coding: utf-8 -*-
"""Bro/Zeek typing annotations."""

import functools
import types
import warnings

import zlogging._typing as typing
from zlogging._exc import BroDeprecationWarning
from zlogging.types import (AddrType, BaseType, BoolType, CountType, DoubleType, EnumType,
                            IntervalType, IntType, PortType, RecordType, SetType, StringType,
                            SubnetType, TimeType, VectorType, _data)

__all__ = [
    'zeek_addr', 'zeek_bool', 'zeek_count', 'zeek_double', 'zeek_enum',
    'zeek_interval', 'zeek_int', 'zeek_port', 'zeek_record', 'zeek_set',
    'zeek_string', 'zeek_subnet', 'zeek_time', 'zeek_vector',
]

zeek_addr = typing.TypeVar('addr', bound=AddrType)
"""type: Zeek ``addr`` data type."""
zeek_bool = typing.TypeVar('bool', bound=BoolType)
"""type: Zeek ``bool`` data type."""
zeek_count = typing.TypeVar('count', bound=CountType)
"""type: Zeek ``count`` data type."""
zeek_double = typing.TypeVar('double', bound=DoubleType)
"""type: Zeek ``double`` data type."""
zeek_enum = typing.TypeVar('enum', bound=EnumType)
"""type: Zeek ``enum`` data type."""
zeek_interval = typing.TypeVar('interval', bound=IntervalType)
"""type: Zeek ``interval`` data type."""
zeek_int = typing.TypeVar('int', bound=IntType)
"""type: Zeek ``int`` data type."""
zeek_port = typing.TypeVar('port', bound=PortType)
"""type: Zeek ``port`` data type."""
zeek_string = typing.TypeVar('string', bound=StringType)
"""type: Zeek ``string`` data type."""
zeek_subnet = typing.TypeVar('subnet', bound=SubnetType)
"""type: Zeek ``subnet`` data type."""
zeek_time = typing.TypeVar('time', bound=TimeType)
"""type: Zeek ``time`` data type."""

zeek_record = types.new_class('record', (RecordType,))
zeek_set = types.new_class('set', (SetType, typing.Generic[_data]))
zeek_vector = types.new_class('vector', (VectorType, typing.Generic[_data]))


def _deprecated(zeek_type: BaseType) -> BaseType:
    """Use of 'bro' is deprecated, please use 'zeek' instead."""

    def issue(func: typing.Callable[..., typing.Any]) -> typing.Callable[..., typing.Any]:
        """Issue deprecation warnings."""
        @functools.wraps(func)
        def wrapper(*args: typing.Args, **kwargs: typing.Kwargs) -> typing.Any:
            print(func)
            warnings.warn("Use of 'bro_%(name)s' is deprecated. "
                          "Please use 'zeek_%(name)s' instead." % dict(name=zeek_type), BroDeprecationWarning)
            return func(*args, **kwargs)
        return wrapper

    class DeprecatedType(zeek_type):

        def __new__(cls, *args: typing.Args, **kwargs: typing.Kwargs) -> BaseType:
            for name in dir(cls):
                attr = getattr(cls, name)
                if not isinstance(attr, types.FunctionType):
                    continue
                setattr(cls, name, issue(attr))
            return super().__new__(cls, *args, **kwargs)

    return DeprecatedType


bro_addr = typing.TypeVar('bro_addr', bound=AddrType)
"""type: Bro ``addr`` data type."""
bro_bool = typing.TypeVar('bro_bool', bound=BoolType)
"""type: Bro ``bool`` data type."""
bro_count = typing.TypeVar('bro_count', bound=CountType)
"""type: Bro ``count`` data type."""
bro_double = typing.TypeVar('bro_double', bound=DoubleType)
"""type: Bro ``double`` data type."""
bro_enum = typing.TypeVar('bro_enum', bound=EnumType)
"""type: Bro ``enum`` data type."""
bro_interval = typing.TypeVar('bro_interval', bound=IntervalType)
"""type: Bro ``interval`` data type."""
bro_int = typing.TypeVar('bro_int', bound=IntType)
"""type: Bro ``int`` data type."""
bro_port = typing.TypeVar('bro_port', bound=PortType)
"""type: Bro ``port`` data type."""
bro_string = typing.TypeVar('bro_string', bound=StringType)
"""type: Bro ``string`` data type."""
bro_subnet = typing.TypeVar('bro_subnet', bound=SubnetType)
"""type: Bro ``subnet`` data type."""
bro_time = typing.TypeVar('bro_time', bound=TimeType)
"""type: Bro ``time`` data type."""

bro_record = types.new_class('bro_record', (RecordType,))
bro_set = types.new_class('bro_set', (SetType, typing.Generic[_data]))
bro_vector = types.new_class('bro_vector', (VectorType, typing.Generic[_data]))
