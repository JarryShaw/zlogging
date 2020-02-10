# -*- coding: utf-8 -*-
"""Auxiliary functions."""

import collections
import decimal
import itertools
import math
import textwrap
import warnings

import zlogging._typing as typing
from zlogging._exc import BroDeprecationWarning
from zlogging._typing import GenericMeta

__all__ = ['readline', 'decimal_toascii', 'float_toascii', 'unicode_escape', 'expand_typing']


def readline(file: typing.BinaryFile, separator: bytes = b'\x09',
             maxsplit: int = -1, decode: bool = False) -> typing.List[typing.AnyStr]:
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


def decimal_toascii(data: typing.Decimal, infinite: str = None) -> str:
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


def float_toascii(data: float, infinite: str = None) -> str:
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
        '\\t'
        >>> unicode_escape(b'\\t')
        '\\x09'

    """
    return ''.join(map(lambda s: '\\x' % s, textwrap.wrap(string.hex(), 2)))


def expand_typing(cls: object, exc: typing.Optional[ValueError] = None) -> typing.Dict[str, typing.Any]:
    """Expand typing annotations.

    Args:
        cls (:class:`~zlogging.model.Model` or :class:`~zlogging.types.RecordType` object):
            a variadic class which supports `PEP 484`_ style attribute typing
            annotations
        exc: (:obj:`ValueError`, optional): exception to be used in case of
            inconsistent values for ``unset_field``, ``empty_field``
            and ``set_separator``

    Returns:
        :obj:`Dict[str, Any]`: The returned dictionary contains the
            following directives:

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
    from zlogging.types import _GenericType, _SimpleType, _VariadicType, BaseType  # pylint: disable=import-outside-toplevel

    if exc is None:
        exc = ValueError

    inited = False
    unset_field = b'-'
    empty_field = b'(empty)'
    set_separator = b','

    def register(name: str, field: BaseType):
        """Field registry."""
        existed = fields.get(name)
        if existed is not None and type(field) != type(existed):
            raise exc('inconsistent data type of %r field: %s and %s' % (name, field, existed))
        fields[name] = field

    fields = collections.OrderedDict()
    record_fields = collections.OrderedDict()
    for name, attr in itertools.chain(getattr(cls, '__annotations__', dict()).items(), cls.__dict__.items()):
        if not isinstance(attr, BaseType):
            if isinstance(attr, typing.TypeVar):
                type_name = attr.__name__
                bound = attr.__bound__

                if isinstance(bound, _SimpleType):
                    attr = bound
                elif isinstance(bound, type) and issubclass(bound, _SimpleType):
                    attr = bound()
                else:
                    continue

                if type_name.startswith('bro'):
                    warnings.warn("Use of 'bro_%(name)s' is deprecated. "
                                  "Please use 'zeek_%(name)s' instead." % dict(name=attr), BroDeprecationWarning)  # pylint: disable=line-too-long
            elif isinstance(attr, GenericMeta) and _GenericType in attr.mro():
                origin = attr.__origin__
                parameter = attr.__parameters__[0]

                if isinstance(parameter, typing.TypeVar):
                    bound = parameter.__bound__
                    if issubclass(bound, _SimpleType):
                        type_name = parameter.__name__
                        element_type = bound()
                        if type_name.startswith('bro'):
                            warnings.warn("Use of 'bro_%(name)s' is deprecated. "
                                          "Please use 'zeek_%(name)s' instead." % dict(name=element_type), BroDeprecationWarning)  # pylint: disable=line-too-long
                    else:
                        element_type = bound
                elif isinstance(parameter, type) and issubclass(parameter, _SimpleType):
                    element_type = parameter()
                else:
                    element_type = parameter

                type_name = origin.__name__
                attr = origin(element_type=element_type)
                if type_name.startswith('bro'):
                    warnings.warn("Use of 'bro_%(name)s' is deprecated. "
                                  "Please use 'zeek_%(name)s' instead." % dict(name=attr), BroDeprecationWarning)  # pylint: disable=line-too-long
            elif isinstance(attr, type) and issubclass(attr, BaseType):
                attr = attr()
            else:
                continue

        if isinstance(attr, _VariadicType):
            for elm_name, elm_field in attr.element_mapping.items():
                register('%s.%s' % (name, elm_name), elm_field)
            record_fields[name] = attr
        else:
            register(name, attr)

        if not inited:
            unset_field = attr.unset_field
            empty_field = attr.empty_field
            set_separator = attr.set_separator
            inited = True
            continue

        if unset_field != attr.unset_field:
            raise exc("inconsistent value of 'unset_field': %r and %r" % (unset_field, attr.unset_field))  # pylint: disable=line-too-long
        if empty_field != attr.empty_field:
            raise exc("inconsistent value of 'empty_field': %r and %r" % (empty_field, attr.empty_field))  # pylint: disable=line-too-long
        if set_separator != attr.set_separator:
            raise exc("inconsistent value of 'set_separator': %r and %r" % (set_separator, attr.set_separator))  # pylint: disable=line-too-long

    return dict(
        fields=fields,
        record_fields=record_fields,
        unset_field=unset_field,
        empty_field=empty_field,
        set_separator=set_separator,
    )
