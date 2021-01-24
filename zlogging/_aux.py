# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Auxiliary functions."""

import collections
import decimal
import itertools
import math
import textwrap
from typing import TYPE_CHECKING, cast, overload

from typing_inspect import get_args, get_origin, is_generic_type, is_typevar

if TYPE_CHECKING:
    from collections import OrderedDict
    from decimal import Decimal
    from io import BufferedReader as BinaryFile
    from typing import List, Optional, Type, TypeVar, Union

    from typing_extensions import Literal

    from zlogging._typing import ExpandedTyping
    from zlogging.model import Model
    from zlogging.types import RecordType

__all__ = ['readline', 'decimal_toascii', 'float_toascii', 'unicode_escape', 'expand_typing']


@overload
def readline(file: 'BinaryFile', seperator: bytes = b'\x09', maxsplit: int = -1) -> 'List[bytes]': ...  # pylint: disable=redefined-outer-name
@overload
def readline(file: 'BinaryFile', seperator: bytes, decode: 'Literal[False]') -> 'List[bytes]': ...  # pylint: disable=redefined-outer-name
@overload
def readline(file: 'BinaryFile', seperator: bytes, decode: 'Literal[True]') -> 'List[str]': ...  # pylint: disable=redefined-outer-name
@overload
def readline(file: 'BinaryFile', seperator: bytes, maxsplit: int,
             decode: 'Literal[False]') -> 'List[bytes]': ...  # pylint: disable=redefined-outer-name
@overload
def readline(file: 'BinaryFile', seperator: bytes, maxsplit: int,
             decode: 'Literal[True]') -> 'List[str]': ...  # pylint: disable=redefined-outer-name
def readline(file: 'BinaryFile', separator: bytes = b'\x09',  # type: ignore[misc]
             maxsplit: int = -1, decode: bool = False) -> 'Union[List[str], List[bytes]]':  # pylint: disable=redefined-outer-name
    """Wrapper for :meth:`file.readline` function.

    Args:
        file: Log file object opened in binary mode.
        separator: Data separator.
        maxsplit: Maximum number of splits to do; see :meth:`bytes.split`
            and :meth:`str.split` for more information.
        decode: If decide the buffered string with ``ascii`` encoding.

    Returns:
        The splitted line as a :obj:`list` of :obj:`bytes`, or as :obj:`str` if
        ``decode`` if set to ``True``.

    """
    line = file.readline().strip()
    if decode:
        return line.decode('ascii').split(separator.decode('ascii'), maxsplit=maxsplit)
    return line.split(separator, maxsplit)


def decimal_toascii(data: 'Decimal', infinite: 'Optional[str]' = None) -> str:
    """Convert :obj:`decimal.Decimal` to ASCII.

    Args:
        data: A :obj:`decimal.Decimal` object.
        infinite: The ASCII representation of infinite numbers (``NaN`` and infinity).

    Returns:
        The converted ASCII string.

    Example:
        When converting a :obj:`decimal.Decimal` object, for example::

            >>> d = decimal.Decimal('-123.123456789')

        the function will preserve only **6 digits** of its fractional part,
        i.e.::

            >>> decimal_toascii(d)
            '-123.123456'

    Note:
        Infinite numbers, i.e. ``NaN`` and infinity (``inf``), will be
        converted as the value specified in ``infinite``, in default the string
        representation of the number itself, i.e.:

        * ``NaN`` -> ``'NaN'``
        * Infinity -> ``'Infinity'``

    """
    if data.is_infinite():
        if infinite is None:
            return str(data)
        return infinite
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


def float_toascii(data: float, infinite: 'Optional[str]' = None) -> str:
    """Convert :obj:`float` to ASCII.

    Args:
        data: A :obj:`float` number.
        infinite: The ASCII representation of infinite numbers (``NaN`` and infinity).

    Returns:
        The converted ASCII string.

    Example:
        When converting a :obj:`float` number, for example::

            >>> f = -123.123456789

        the function will preserve only **6 digits** of its fractional part,
        i.e.::

            >>> float_toascii(f)
            '-123.123456'

    Note:
        Infinite numbers, i.e. ``NaN`` and infinity (``inf``), will be
        converted as the value specified in ``infinite``, in default the string
        representation of the number itself, i.e.:

        * ``NaN`` -> ``'nan'``
        * Infinity -> ``'inf'``

    """
    if not math.isfinite(data):
        if infinite is None:
            return str(data)
        return infinite
    int_part, flt_part = str(data).split('.')
    return '%s.%s%s' % (int_part,
                        flt_part[:6],
                        '0' * (6 - len(flt_part)))


def unicode_escape(string: bytes) -> str:
    """Conterprocess of :meth:`bytes.decode('unicode_escape')`.

    Args:
        string: The bytestring to be escaped.

    Returns:
        The escaped bytestring as an encoded string

    Example:

        >>> b'\\x09'.decode('unicode_escape')
        '\\\\t'
        >>> unicode_escape(b'\\t')
        '\\\\x09'

    """
    return ''.join(map(lambda s: '\\x%s' % s, textwrap.wrap(string.hex(), 2)))


def expand_typing(cls: 'Union[Model, Type[Model], RecordType, Type[RecordType]]',
                  exc: 'Optional[Type[ValueError]]' = None) -> 'ExpandedTyping':
    """Expand typing annotations.

    Args:
        cls (:class:`~zlogging.model.Model` or :class:`~zlogging.types.RecordType` object):
            a variadic class which supports `PEP 484`_ style attribute typing
            annotations
        exc: (:obj:`ValueError`, optional): exception to be used in case of
            inconsistent values for ``unset_field``, ``empty_field``
            and ``set_separator``

    Returns:
        :obj:`Dict[str, Any]`: The returned dictionary contains the following directives:

            * ``fields`` (:obj:`OrderedDict` mapping :obj:`str` and :class:`~zlogging.types.BaseType`):
                a mapping proxy of field names and their corresponding data
                types, i.e. an instance of a :class:`~zlogging.types.BaseType`
                subclass

            * ``record_fields`` (:obj:`OrderedDict` mapping :obj:`str` and :class:`~zlogging.types.RecordType`):
                a mapping proxy for fields of ``record`` data type, i.e. an
                instance of :class:`~zlogging.types.RecordType`

            * ``unset_fields`` (:obj:`bytes`): placeholder for unset field

            * ``empty_fields`` (:obj:`bytes`): placeholder for empty field

            * ``set_separator`` (:obj:`bytes`): separator for ``set``/``vector`` fields

    Warns:
        BroDeprecationWarning: Use of ``bro_*`` prefixed typing annotations.

    Raises:
        :exc:`ValueError`: In case of inconsistent values for ``unset_field``,
            ``empty_field`` and ``set_separator``.

    Example:
        Define a custom log data model from :class:`~zlogging.model.Model` using
        the prefines Bro/Zeek data types, or subclasses of
        :class:`~zlogging.types.BaseType`::

            class MyLog(Model):
                field_one = StringType()
                field_two = SetType(element_type=PortType)

        Or you may use type annotations as `PEP 484`_ introduced when declaring
        data models. All available type hints can be found in
        :mod:`zlogging.typing`::

            class MyLog(Model):
                field_one: zeek_string
                field_two: zeek_set[zeek_port]

        However, when mixing annotations and direct assignments, annotations
        will take proceedings, i.e. the function shall process first typing
        annotations then ``cls`` attribute assignments. Should there be any
        conflicts, the ``exc`` will be raised.

    Note:
        Fields of :class:`zlogging.types.RecordType` type will be expanded as
        plain fields of the ``cls``, i.e. for the variadic class as below::

            class MyLog(Model):
                record = RecrodType(one=StringType(),
                                    two=VectorType(element_type=CountType()))

        will have the following fields:

        * ``record.one`` -> ``string`` data type
        * ``record.two`` -> ``vector[count]`` data type

    .. _PEP 484:
        https://www.python.org/dev/peps/pep-0484/

    """
    from zlogging.types import (BaseType, _GenericType,  # pylint: disable=import-outside-toplevel
                                _SimpleType, _VariadicType)

    if exc is None:
        exc = ValueError

    inited = False
    unset_field = b'-'
    empty_field = b'(empty)'
    set_separator = b','

    def register(name: str, field: 'Union[_SimpleType, _GenericType]') -> None:
        """Field registry."""
        existed = fields.get(name)
        if existed is not None and field.zeek_type != existed.zeek_type:
            raise exc(f'inconsistent data type of {name!r} field: {field} and {existed}')  # type: ignore[misc]
        fields[name] = field

    fields = collections.OrderedDict()  # type: OrderedDict[str, Union[_SimpleType, _GenericType]]
    record_fields = collections.OrderedDict()  # type: OrderedDict[str, _VariadicType]
    for name, attr in itertools.chain(getattr(cls, '__annotations__', dict()).items(), cls.__dict__.items()):
        # type instances
        if isinstance(attr, BaseType):
            if isinstance(attr, _VariadicType):
                for elm_name, elm_field in attr.element_mapping.items():
                    register(f'{name}.{elm_name}', elm_field)
                record_fields[name] = attr
            else:
                register(name, attr)  # type: ignore[arg-type]

        # uninitialised type classes
        elif isinstance(attr, type) and issubclass(attr, BaseType):
            attr = attr()

        # simple typing types
        elif is_typevar(attr):
            if TYPE_CHECKING:
                attr = cast('TypeVar', attr)

            bound = attr.__bound__
            if bound and issubclass(bound, _SimpleType):
                attr = bound()
            else:
                continue

        # generic typing types
        elif is_generic_type(attr) and issubclass(attr, _GenericType):
            origin = get_origin(attr)
            parameter = get_args(attr)[0]

            # uninitialised type classes
            if isinstance(parameter, type) and issubclass(parameter, _SimpleType):
                element_type = parameter()

            # simple typing types
            elif is_typevar(parameter):
                if TYPE_CHECKING:
                    parameter = cast('TypeVar', parameter)
                bound = parameter.__bound__
                if bound and issubclass(bound, _SimpleType):
                    element_type = bound()
                else:
                    element_type = bound  # type: ignore[assignment]

            else:
                element_type = parameter  # type: ignore[assignment]
            attr = origin(element_type=element_type)\

        else:
            continue

        if not inited:
            unset_field = attr.unset_field
            empty_field = attr.empty_field
            set_separator = attr.set_separator
            inited = True
            continue

        if unset_field != attr.unset_field:
            raise exc(f"inconsistent value of 'unset_field': {unset_field!r} and {attr.unset_field!r}")
        if empty_field != attr.empty_field:
            raise exc(f"inconsistent value of 'empty_field': {empty_field!r} and {attr.empty_field!r}")
        if set_separator != attr.set_separator:
            raise exc("inconsistent value of 'set_separator': {set_separator!r} and {attr.set_separator!r}")

    return {
        'fields': fields,
        'record_fields': record_fields,
        'unset_field': unset_field,
        'empty_field': empty_field,
        'set_separator': set_separator,
    }
