# -*- coding: utf-8 -*-
"""Exceptions & warnings."""

import json

import blogging._typing as typing


class ZeekException(Exception):
    """Base exception."""


class ZeekWarning(Warning):
    """Base warning."""


class ParserError(ZeekException, ValueError):
    """Error when parsing logs.

    Attributes:
        msg: the unformatted error message
        field: the field name where parsing failed
        lineno: the line corresponding to the failure

    """

    def __init__(self, msg: str,
                 lineno: typing.Optional[int] = None,
                 field: typing.Optional[str] = None):
        """Initialisation.

        Args:
            msg: the unformatted error message
            lineno (:obj:`int`, optional): the line corresponding to the failure
            field (:obj:`str`, optional): the field name where parsing failed

        """
        if lineno is None:
            errmsg = msg
        elif field is None:
            errmsg = '%s: line %d' % (msg, lineno)
        else:
            errmsg = '%s: line %d (field %d)' % (msg, lineno, field)
        super().__init__(self, errmsg)

        self.msg = msg
        self.field = field
        self.lineno = lineno

    def __reduce__(self):
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONParserError(ParserError, json.JSONDecodeError):
    """Error when parsing JSON log."""


class ASCIIPaserError(ParserError):
    """Error when parsing ASCII log."""


class WriterError(ZeekException, TypeError):
    """Error when writing logs.

    Attributes:
        msg: the unformatted error message
        field: the field name where writing failed
        lineno: the line corresponding to the failure

    """

    def __init__(self, msg: str,
                 lineno: typing.Optional[int] = None,
                 field: typing.Optional[str] = None):
        """Initialisation.

        Args:
            msg: the unformatted error message
            lineno (:obj:`int`, optional): the line corresponding to the failure
            field (:obj:`str`, optional): the field name where writing failed

        """
        if lineno is None:
            errmsg = msg
        elif field is None:
            errmsg = '%s: line %d' % (msg, lineno)
        else:
            errmsg = '%s: line %d (field %d)' % (msg, lineno, field)
        super().__init__(self, errmsg)

        self.msg = msg
        self.field = field
        self.lineno = lineno

    def __reduce__(self):
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONWriterError(WriterError):
    """Error when writing JSON logs."""


class ASCIIWriterError(WriterError):
    """Error when writing ASCII logs."""


class WriterFormatError(WriterError, ValueError):
    """Unsupported format."""


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
