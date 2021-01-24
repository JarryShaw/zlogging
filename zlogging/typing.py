# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Bro/Zeek typing annotations."""

import warnings
from typing import TYPE_CHECKING, Generic, TypeVar

from zlogging._exc import BroDeprecationWarning
from zlogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType, IntType,
                    PortType, RecordType, SetType, StringType, SubnetType, TimeType, VectorType)

__all__ = [
    'zeek_addr', 'zeek_bool', 'zeek_count', 'zeek_double', 'zeek_enum',
    'zeek_interval', 'zeek_int', 'zeek_port', 'zeek_record', 'zeek_set',
    'zeek_string', 'zeek_subnet', 'zeek_time', 'zeek_vector',

    'bro_addr', 'bro_bool', 'bro_count', 'bro_double', 'bro_enum',
    'bro_interval', 'bro_int', 'bro_port', 'bro_record', 'bro_set',
    'bro_string', 'bro_subnet', 'bro_time', 'bro_vector',
]

_T = TypeVar('_T', bound='Type[BaseType]')
_S = TypeVar('_S', bound='_SimpleType')
if TYPE_CHECKING:
    from typing import Any, Type

    from zlogging.types import BaseType, _SimpleType


def _deprecated(zeek_type: '_T') -> '_T':
    """Use of 'bro' is deprecated, please use 'zeek' instead."""
    class DeprecatedType(zeek_type):  # type: ignore[misc,valid-type]
        def __init__(self, *args: 'Any', **kwargs: 'Any') -> None:
            warnings.warn("Use of 'bro_%(name)s' is deprecated. "
                          "Please use 'zeek_%(name)s' instead." % dict(name=zeek_type), BroDeprecationWarning)
            super().__init__(*args, **kwargs)

    DeprecatedType.__doc__ = zeek_type.__doc__
    return DeprecatedType  # type: ignore[return-value]


###########################################################
# Zeek typing types

#: Zeek ``addr`` data type.
zeek_addr = TypeVar('zeek_addr', bound='AddrType')
#: Zeek ``bool`` data type.
zeek_bool = TypeVar('zeek_bool', bound='BoolType')
#: Zeek ``count`` data type.
zeek_count = TypeVar('zeek_count', bound='CountType')
#: Zeek ``double`` data type.
zeek_double = TypeVar('zeek_double', bound='DoubleType')
#: Zeek ``enum`` data type.
zeek_enum = TypeVar('zeek_enum', bound='EnumType')
#: Zeek ``interval`` data type.
zeek_interval = TypeVar('zeek_interval', bound='IntervalType')
#: Zeek ``int`` data type.
zeek_int = TypeVar('zeek_int', bound='IntType')
#: Zeek ``port`` data type.
zeek_port = TypeVar('zeek_port', bound='PortType')
#: Zeek ``string`` data type.
zeek_string = TypeVar('zeek_string', bound='StringType')
#: Zeek ``subnet`` data type.
zeek_subnet = TypeVar('zeek_subnet', bound='SubnetType')
#: Zeek ``time`` data type.
zeek_time = TypeVar('zeek_time', bound='TimeType')


class zeek_set(SetType, Generic[_S]):
    """Zeek ``set`` data type."""


class zeek_vector(VectorType, Generic[_S]):
    """Zeek ``vector`` data type."""


class zeek_record(RecordType):
    """Zeek ``record`` data type."""


###########################################################
# Bro typing types


@_deprecated
class _BroAddrType(AddrType):
    """Bro ``addr`` data type."""


@_deprecated
class _BroBoolType(BoolType):
    """Bro ``bool`` data type."""


@_deprecated
class _BroCountType(CountType):
    """Bro ``count`` data type."""


@_deprecated
class _BroDoubleType(DoubleType):
    """Bro ``double`` data type."""


@_deprecated
class _BroEnumType(EnumType):
    """Bro ``enum`` data type."""


@_deprecated
class _BroIntervalType(IntervalType):
    """Bro ``interval`` data type."""


@_deprecated
class _BroIntType(IntType):
    """Bro ``int`` data type."""


@_deprecated
class _BroPortType(PortType):
    """Bro ``port`` data type."""


@_deprecated
class _BroStringType(StringType):
    """Bro ``string`` data type."""


@_deprecated
class _BroSubnetType(SubnetType):
    """Bro ``subnet`` data type."""


@_deprecated
class _BroTimeType(TimeType):
    """Bro ``time`` data type."""


#: Bro ``addr`` data type.
bro_addr = TypeVar('bro_addr', bound='_BroAddrType')
#: Bro ``bool`` data type.
bro_bool = TypeVar('bro_bool', bound='_BroBoolType')
#: Bro ``count`` data type.
bro_count = TypeVar('bro_count', bound='_BroCountType')
#: Bro ``double`` data type.
bro_double = TypeVar('bro_double', bound='_BroDoubleType')
#: Bro ``enum`` data type.
bro_enum = TypeVar('bro_enum', bound='_BroEnumType')
#: Bro ``interval`` data type.
bro_interval = TypeVar('bro_interval', bound='_BroIntervalType')
#: Bro ``int`` data type.
bro_int = TypeVar('bro_int', bound='_BroIntType')
#: Bro ``port`` data type.
bro_port = TypeVar('bro_port', bound='_BroPortType')
#: Bro ``string`` data type.
bro_string = TypeVar('bro_string', bound='_BroStringType')
#: Bro ``subnet`` data type.
bro_subnet = TypeVar('bro_subnet', bound='_BroSubnetType')
#: Bro ``time`` data type.
bro_time = TypeVar('bro_time', bound='_BroTimeType')


@_deprecated
class bro_set(SetType, Generic[_S]):
    """Bro ``set`` data type."""


@_deprecated
class bro_vector(VectorType, Generic[_S]):
    """Bro ``vector`` data type."""


@_deprecated
class bro_record(RecordType):
    """Bro ``record`` data type."""
