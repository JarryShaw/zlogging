# -*- coding: utf-8 -*-
"""Auxiliary function."""

import collections
import decimal
import itertools
import textwrap
import warnings
from typing import _GenericAlias

import blogging._typing as typing
from blogging._exc import BroDeprecationWarning

__all__ = ['readline', 'decimal_toascii', 'float_toascii', 'unicode_escape', 'expand_typing']


def readline(file: typing.BinaryFile, separator: bytes = b'\x09',
             maxsplit: int = -1, decode: bool = False) -> typing.List[typing.AnyStr]:
    """Wrapper for ``readline`` function.

    Args:
        file: log file object opened in binary mode
        separator: data separator
        maxsplit: maximum number of splits to do; see :meth:`bytes.split`
            and :meth:`str.split` for more information
        decode: if decide the buffered string with ``ascii`` encoding

    Returns:
        The splitted line as a :obj:`list` of :obj:`bytes`, or as :obj:`str` if
        ``decode`` if set to ``True``.

    """
    line = file.readline().strip()
    if decode:
        return line.decode('ascii').split(separator.decode('ascii'), maxsplit=maxsplit)
    return line.split(separator, maxsplit)


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


def unicode_escape(string: bytes) -> str:
    """Conterprocess of ``bytes.decode('unicode_escape')``."""
    return ''.join(map(lambda s: '\\x' % s, textwrap.wrap(string.hex(), 2)))


def expand_typing(cls: object, exc: ValueError) -> typing.Dict[str, typing.Any]:
    """Expand model typing annotations."""
    from blogging.types import _GenericType, _SimpleType, _VariadicType, Type  # pylint: disable=import-outside-toplevel

    inited = False
    unset_field = b'-'
    empty_field = b'(empty)'
    set_separator = b','

    def register(name: str, field: Type):
        """Field registry."""
        existed = fields.get(name)
        if existed is not None and type(field) != type(existed):
            raise exc('inconsistent data type of %r field: %s and %s' % (name, field, existed))
        fields[name] = field

    fields = collections.OrderedDict()
    record_fields = collections.OrderedDict()
    for name, attr in itertools.chain(getattr(cls, '__annotations__', dict()).items(), cls.__dict__.items()):
        if not isinstance(attr, Type):
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
            elif isinstance(attr, _GenericAlias) and _GenericType in attr.mro():
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
            elif isinstance(attr, type) and issubclass(attr, Type):
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
