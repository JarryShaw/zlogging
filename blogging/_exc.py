# -*- coding: utf-8 -*-
"""Exceptions & warnings."""

import json

import blogging._typing as typing


class ParserError(ValueError):
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


class ParserWarning(UserWarning):
    """Warning when parsing logs."""


class JSONParserWarning(ParserWarning):
    """Warning when parsing logs in JSON format."""


class ASCIIParserWarning(ParserWarning):
    """Warning when parsing logs in ASCII format."""


class ZeekValueError(ValueError):
    """Invalid Bro/Zeek data value."""


class ZeekValueWarning(UserWarning):
    """Dubious Bro/Zeek data value."""


class ModelError(TypeError):
    """Invalid model data."""
