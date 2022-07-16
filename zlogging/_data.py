# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Data classes for parsed logs."""

import abc
import dataclasses
from typing import TYPE_CHECKING

__all__ = [
    'ASCIIInfo', 'JSONInfo'
]

if TYPE_CHECKING:
    from datetime import datetime as DateTimeType
    from os import PathLike
    from typing import Literal

    from zlogging.model import Model


class Info(metaclass=abc.ABCMeta):
    """Parsed log info.

    The parsed log will be stored as in this :func:`dataclass <dataclasses.dataclass>`,
    as introduced in :pep:`557`.

    """

    @property
    @abc.abstractmethod
    def format(self) -> str:
        """Log file format."""


@dataclasses.dataclass(frozen=True)
class ASCIIInfo(Info):
    """Parsed log info for ASCII logs.

    The ASCII log will be stored as in this :func:`dataclass <dataclasses.dataclass>`,
    as introduced in :pep:`557`.

    Args:
        path: The value is specified in the ASCII log file
            under ``# path`` directive.
        open: The value is specified in the ASCII log file
            under ``# open`` directive.
        close: The value is specified in the ASCII log file
            under ``# close`` directive.
        data: The log records parsed as a :obj:`list` of
            :class:`~zlogging.model.Model` per line.
        exit_with_error: When exit with error, the ASCII log
            file doesn't has a ``# close`` directive.

    """

    @property
    def format(self) -> 'Literal["ascii"]':
        """Log file format."""
        return 'ascii'

    #: Log path. The value is specified in the ASCII log file
    #: under ``# path`` directive.
    path: 'PathLike[str]'
    #: Log open time. The value is specified in the ASCII log
    #: file under ``# open`` directive.
    open: 'DateTimeType'
    #: Log close time. The value is specified in the ASCII log
    #: file under ``# close`` directive.
    close: 'DateTimeType'
    #: Log records. The log records parsed as a :obj:`list` of
    #: :class:`~zlogging.model.Model` per line.
    data: 'list[Model]'
    #: Log exit with error. When exit with error, the ASCII log
    #: file doesn't has a ``# close`` directive.
    exit_with_error: 'bool'


@dataclasses.dataclass(frozen=True)
class JSONInfo(Info):
    """Parsed log info for JSON logs.

    The JSON log will be stored as in this :func:`dataclass <dataclasses.dataclass>`,
    as introduced in :pep:`557`.

    Args:
        data: The log records parsed as a :obj:`list` of
            :class:`~zlogging.model.Model` per line.

    """

    @property
    def format(self) -> 'Literal["json"]':
        """Log file format."""
        return 'json'

    #: Log records. The log records parsed as a :obj:`list` of
    #: :class:`~zlogging.model.Model` per line.
    data: 'list[Model]'
