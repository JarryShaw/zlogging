# -*- coding: utf-8 -*-
"""Exceptions & warnings."""

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional, Tuple, Type


class ZeekException(Exception):
    """Base exception."""


class ZeekWarning(Warning):
    """Base warning."""


class ParserError(ZeekException, ValueError):
    """Error when parsing logs.

    Args:
        msg (str): The unformatted error message.
        lineno (:obj:`int`, optional): The line corresponding to the failure.
        field (:obj:`str`, optional): The field name where parsing failed.

    Attributes:
        msg (str): The unformatted error message.
        field: (str) The field name where parsing failed.
        lineno (int): The line corresponding to the failure.

    """

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

    def __reduce__(self) -> 'Tuple[Type[ParserError], Tuple[str, Optional[int], Optional[str]]]':
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONParserError(ParserError, json.JSONDecodeError):  # type: ignore[misc]
    """Error when parsing JSON log.

    Args:
        msg (str): The unformatted error message.
        lineno (:obj:`int`, optional): The line corresponding to the failure.
        field (:obj:`str`, optional): The field name where parsing failed.

    Attributes:
        msg (str): The unformatted error message.
        field: (str) The field name where parsing failed.
        lineno (int): The line corresponding to the failure.

    """


class ASCIIPaserError(ParserError):
    """Error when parsing ASCII log.

    Args:
        msg (str): The unformatted error message.
        lineno (:obj:`int`, optional): The line corresponding to the failure.
        field (:obj:`str`, optional): The field name where parsing failed.

    Attributes:
        msg (str): The unformatted error message.
        field: (str) The field name where parsing failed.
        lineno (int): The line corresponding to the failure.

    """


class WriterError(ZeekException, TypeError):
    """Error when writing logs.

    Args:
        msg (str): The unformatted error message.
        lineno (:obj:`int`, optional): The line corresponding to the failure.
        field (:obj:`str`, optional): The field name where writing failed.

    Attributes:
        msg (str): The unformatted error message.
        field (str): The field name where writing failed.
        lineno (int): The line corresponding to the failure.

    """

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

    def __reduce__(self) -> 'Tuple[Type[WriterError], Tuple[str, Optional[int], Optional[str]]]':
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONWriterError(WriterError):
    """Error when writing JSON logs.

    Args:
        msg (str): The unformatted error message.
        lineno (:obj:`int`, optional): The line corresponding to the failure.
        field (:obj:`str`, optional): The field name where writing failed.

    Attributes:
        msg (str): The unformatted error message.
        field (str): The field name where writing failed.
        lineno (int): The line corresponding to the failure.

    """


class ASCIIWriterError(WriterError):
    """Error when writing ASCII logs.

    Args:
        msg (str): The unformatted error message.
        lineno (:obj:`int`, optional): The line corresponding to the failure.
        field (:obj:`str`, optional): The field name where writing failed.

    Attributes:
        msg (str): The unformatted error message.
        field (str): The field name where writing failed.
        lineno (int): The line corresponding to the failure.

    """


class WriterFormatError(WriterError, ValueError):
    """Unsupported format.

    Args:
        msg (str): the unformatted error message
        lineno (:obj:`int`, optional): the line corresponding to the failure
        field (:obj:`str`, optional): the field name where writing failed

    Attributes:
        msg (str): the unformatted error message
        field (str): the field name where writing failed
        lineno (int): the line corresponding to the failure

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
