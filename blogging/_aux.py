# -*- coding: utf-8 -*-
"""Auxiliary function."""

import decimal

import blogging._typing as typing

__all__ = ['readline', 'decimal_toascii', 'float_toascii']


def readline(file: typing.BinaryFile, separator: bytes = b'\x09',
             maxsplit: int = -1, decode: bool = False) -> typing.List[typing.AnyStr]:
    """Wrapper for ``readline`` function.

    Args:
        file: log file object opened in binary mode
        seperator: data separator
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
