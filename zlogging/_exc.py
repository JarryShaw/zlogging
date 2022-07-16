# -*- coding: utf-8 -*-
"""Exceptions & warnings."""

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional, Type


class ZeekException(Exception):
    """Base exception."""


class ZeekWarning(Warning):
    """Base warning."""


class ParserError(ZeekException, ValueError):
    """Error when parsing logs.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """
    #: The unformatted error message.
    msg: str
    #: The field name where parsing failed.
    field: 'Optional[str]'
    #: The line corresponding to the failure.
    lineno: 'Optional[int]'

    def __init__(self, msg: str, lineno: 'Optional[int]' = None,
                 field: 'Optional[str]' = None) -> None:
        if lineno is None:
            errmsg = msg
        elif field is None:
            errmsg = f'{msg}: line {lineno}'
        else:
            errmsg = f'{msg}: line {lineno} (field {field!r})'
        super().__init__(self, errmsg)

        self.msg = msg
        self.field = field
        self.lineno = lineno

    def __reduce__(self) -> 'tuple[Type[ParserError], tuple[str, Optional[int], Optional[str]]]':
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONParserError(ParserError, json.JSONDecodeError):  # type: ignore[misc]
    """Error when parsing JSON log.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """


class ASCIIParserError(ParserError):
    """Error when parsing ASCII log.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """


class WriterError(ZeekException, TypeError):
    """Error when writing logs.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """
    #: The unformatted error message.
    msg: str
    #: The field name where parsing failed.
    field: 'Optional[str]'
    #: The line corresponding to the failure.
    lineno: 'Optional[int]'

    def __init__(self, msg: str, lineno: 'Optional[int]' = None,
                 field: 'Optional[str]' = None) -> None:
        if lineno is None:
            errmsg = msg
        elif field is None:
            errmsg = f'{msg}: line {lineno}'
        else:
            errmsg = f'{msg}: line {lineno} (field {field!r})'
        super().__init__(self, errmsg)

        self.msg = msg
        self.field = field
        self.lineno = lineno

    def __reduce__(self) -> 'tuple[Type[WriterError], tuple[str, Optional[int], Optional[str]]]':
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONWriterError(WriterError):
    """Error when writing JSON logs.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """


class ASCIIWriterError(WriterError):
    """Error when writing ASCII logs.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """


class WriterFormatError(WriterError, ValueError):
    """Unsupported format.

    Args:
        msg: The unformatted error message.
        lineno: The line corresponding to the failure.
        field: The field name where parsing failed.

    """


class ParserWarning(ZeekWarning, UserWarning):
    """Warning when parsing logs."""


class JSONParserWarning(ParserWarning):
    """Warning when parsing logs in JSON format."""


class ASCIIParserWarning(ParserWarning):
    """Warning when parsing logs in ASCII format."""


class ZeekTypeError(ZeekException, TypeError):
    """Invalid Bro/Zeek data type."""


class ZeekValueError(ZeekException, ValueError):
    """Invalid Bro/Zeek data value."""


class ZeekNotImplemented(ZeekException, NotImplementedError):
    """Method not implemented."""


class ModelError(ZeekException):
    """Invalid model data."""


class ModelTypeError(ModelError, TypeError):
    """Invalid model data type."""


class ModelValueError(ModelError, ValueError):
    """Invalid model data value."""


class ModelFormatError(ModelError, ValueError):
    """Unsupported format."""


class ZeekValueWarning(ZeekWarning, UserWarning):
    """Dubious Bro/Zeek data value."""


class BroDeprecationWarning(ZeekWarning, DeprecationWarning):
    """Bro is now deprecated, use Zeek instead."""
