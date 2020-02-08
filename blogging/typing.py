# -*- coding: utf-8 -*-
"""Bro/Zeek typing annotations."""

import typing

from blogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                            IntType, PortType, SetType, StringType, SubnetType, TimeType,
                            VectorType)

__all__ = [
    'zeek_addr', 'zeek_bool', 'zeek_count', 'zeek_double', 'zeek_enum',
    'zeek_interval', 'zeek_int', 'zeek_port', 'zeek_string', 'zeek_subnet',
    'zeek_time',
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

zeek_set = SetType
zeek_vector = VectorType

bro_addr = zeek_addr
bro_bool = zeek_addr
bro_count = zeek_count
bro_double = zeek_double
bro_enum = zeek_enum
bro_interval = zeek_interval
bro_int = zeek_int
bro_port = zeek_port
bro_set = zeek_set
bro_string = zeek_string
bro_subnet = zeek_subnet
bro_time = zeek_time
bro_vector = zeek_vector
