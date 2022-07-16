# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Bro/Zeek typing annotations."""

import warnings
from typing import TYPE_CHECKING, Generic, TypeVar

from zlogging._exc import BroDeprecationWarning
from zlogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                            IntType, PortType, RecordType, SetType, StringType, SubnetType,
                            TimeType, VectorType)

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


def _deprecated(bro_type: '_T') -> '_T':
    """Use of ``'bro'`` is deprecated, please use ``'zeek'`` instead."""
    name = bro_type.__name__
    orig_init = bro_type.__init__


    def __init__(self: 'BaseType', *args: 'Any', **kwargs: 'Any') -> 'None':
        warnings.warn(f"Use of 'bro_{name}' is deprecated. "
                        f"Please use 'zeek_{name}' instead.", BroDeprecationWarning)
        orig_init(self, *args, **kwargs)

    bro_type.__init__ = __init__  # type: ignore[assignment]
    return bro_type


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
    """Zeek ``set`` data type.

    Notes:
        As a *generic* data type, the class supports the typing proxy as introduced
        :pep:`484`:

        .. code-block:: python

            class MyLog(zeek_record):
                field_one: zeek_set[zeek_str]

        which is the same **at runtime** as following:

        .. code-block:: python

            class MyLog(zeek_record):
                field_one = SetType(element_type=StringType())

    """


class zeek_vector(VectorType, Generic[_S]):
    """Zeek ``vector`` data type.

    Notes:
        As a *generic* data type, the class supports the typing proxy as introduced
        :pep:`484`:

        .. code-block:: python

            class MyLog(zeek_record):
                field_one: zeek_vector[zeek_str]

        which is the same **at runtime** as following:

        .. code-block:: python

            class MyLog(zeek_record):
                field_one = VectorType(element_type=StringType())

    """


class zeek_record(RecordType):
    """Zeek ``record`` data type.

    Notes:
        As a *variadic* data type, it supports the typing proxy as :class:`~typing.TypedDict`,
        introduced in :pep:`589`:

        .. code-block:: python

            class MyLog(zeek_record):
                field_one: zeek_int
                field_two: zeek_set[zeek_port]

        which is the same **at runtime** as following:

        .. code-block:: python

            RecordType(field_one=IntType,
                       field_two=SetType(element_type=PortType))


    See Also:
        See :func:`~zlogging._aux.expand_typing` for more information about the
        processing of typing proxy.

    """


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
    """Bro ``set`` data type.

    See Also:
        See :attr:`~zlogging.typing.zeek_set` for more information.

    """


@_deprecated
class bro_vector(VectorType, Generic[_S]):
    """Bro ``vector`` data type.

    See Also:
        See :attr:`~zlogging.typing.zeek_vector` for more information.

    """


@_deprecated
class bro_record(RecordType):
    """Bro ``record`` data type.

    See Also:
        See :attr:`~zlogging.typing.zeek_record` for more information.

    """
