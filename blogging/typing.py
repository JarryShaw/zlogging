# -*- coding: utf-8 -*-
"""Bro/Zeek typing annotations."""

import functools
import types
import warnings

import blogging._typing as typing
from blogging._exc import BroDeprecationWarning
from blogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                            IntType, PortType, RecordType, SetType, StringType, SubnetType,
                            TimeType, Type, VectorType, _data)

__all__ = [
    'zeek_addr', 'zeek_bool', 'zeek_count', 'zeek_double', 'zeek_enum',
    'zeek_interval', 'zeek_int', 'zeek_port', 'zeek_record', 'zeek_string',
    'zeek_subnet', 'zeek_time',
]

zeek_addr = typing.TypeVar('addr', bound=AddrType)
zeek_bool = typing.TypeVar('bool', bound=BoolType)
zeek_count = typing.TypeVar('count', bound=CountType)
zeek_double = typing.TypeVar('double', bound=DoubleType)
zeek_enum = typing.TypeVar('enum', bound=EnumType)
zeek_interval = typing.TypeVar('interval', bound=IntervalType)
zeek_int = typing.TypeVar('int', bound=IntType)
zeek_port = typing.TypeVar('port', bound=PortType)
zeek_string = typing.TypeVar('string', bound=StringType)
zeek_subnet = typing.TypeVar('subnet', bound=SubnetType)
zeek_time = typing.TypeVar('time', bound=TimeType)

zeek_record = types.new_class('record', (RecordType,))
zeek_set = types.new_class('set', (SetType, typing.Generic[_data]))
zeek_vector = types.new_class('vector', (VectorType, typing.Generic[_data]))


def _deprecated(zeek_type: Type) -> Type:
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

        def __new__(cls, *args: typing.Args, **kwargs: typing.Kwargs) -> Type:
            for name in dir(cls):
                attr = getattr(cls, name)
                if not isinstance(attr, types.FunctionType):
                    continue
                setattr(cls, name, issue(attr))
            return super().__new__(cls, *args, **kwargs)

    return DeprecatedType


bro_addr = typing.TypeVar('bro_addr', bound=AddrType)
bro_bool = typing.TypeVar('bro_bool', bound=BoolType)
bro_count = typing.TypeVar('bro_count', bound=CountType)
bro_double = typing.TypeVar('bro_double', bound=DoubleType)
bro_enum = typing.TypeVar('bro_enum', bound=EnumType)
bro_interval = typing.TypeVar('bro_interval', bound=IntervalType)
bro_int = typing.TypeVar('bro_int', bound=IntType)
bro_port = typing.TypeVar('bro_port', bound=PortType)
bro_string = typing.TypeVar('bro_string', bound=StringType)
bro_subnet = typing.TypeVar('bro_subnet', bound=SubnetType)
bro_time = typing.TypeVar('bro_time', bound=TimeType)

bro_record = types.new_class('bro_record', (RecordType,))
bro_set = types.new_class('bro_set', (SetType, typing.Generic[_data]))
bro_vector = types.new_class('bro_vector', (VectorType, typing.Generic[_data]))
