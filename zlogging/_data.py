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
    from typing import List, Literal

    from zlogging.model import Model


class Info(metaclass=abc.ABCMeta):
    """Parsed log info.

    The parsed log will be stored as in this :obj:`dataclass`, as introduced in
    `PEP 557`_.

    .. _PEP 557:
        https://www.python.org/dev/peps/pep-557/

    """

    @property
    @abc.abstractmethod
    def format(self) -> str:
        """str: Log file format."""


@dataclasses.dataclass(frozen=True)
class ASCIIInfo(Info):
    """Parsed log info for ASCII logs.

    The ASCII log will be stored as in this :obj:`dataclass`, as introduced in
    `PEP 557`_.

    Args:
        path (:obj:`os.PathLike`): The value is specified in the ASCII log file
            under ``# path`` directive.
        open (:obj:`datetime.datetime`): The value is specified in the ASCII
            log file under ``# open`` directive.
        close (:obj:`datetime.datetime`): The value is specified in the ASCII
            log file under ``# close`` directive.
        data (:obj:`list` or :class:`~zlogging.model.Model`): The log records
            parsed as a :obj:`list` of :class:`~zlogging.model.Model` per line.
        exit_with_error (:obj:`bool`): When exit with error, the ASCII log
            file doesn't has a ``# close`` directive.

    .. _PEP 557:
        https://www.python.org/dev/peps/pep-557/

    """

    @property
    def format(self) -> 'Literal["ascii"]':
        """str: Log file format."""
        return 'ascii'

    path: 'PathLike[str]'
    """:obj:`os.PathLike`: Log path.

    The value is specified in the ASCII log file under ``# path`` directive.
    """
    open: 'DateTimeType'
    """:obj:`datetime.datetime`: Log open time.

    The value is specified in the ASCII log file under ``# open`` directive.
    """
    close: 'DateTimeType'
    """:obj:`datetime.datetime`: Log close time.

    The value is specified in the ASCII log file under ``# close`` directive.
    """
    data: 'List[Model]'
    """:obj:`list` of :class:`~zlogging.model.Model`: Log records.

    The log records parsed as a :obj:`list` of :class:`~zlogging.model.Model` per line.
    """
    exit_with_error: bool
    """:obj:`bool`: Log exit with error.

    When exit with error, the ASCII log file doesn't has a ``# close`` directive.
    """


@dataclasses.dataclass(frozen=True)
class JSONInfo(Info):
    """Parsed log info for JSON logs.

    The JSON log will be stored as in this :obj:`dataclass`, as introduced in
    `PEP 557`_.

    Args:
        data (:obj:`list` of :class:`~zlogging.model.Model`): The log records
            parsed as a :obj:`list` of :class:`~zlogging.model.Model` per line.

    .. _PEP 557:
        https://www.python.org/dev/peps/pep-557/

    """

    @property
    def format(self) -> 'Literal["json"]':
        """str: Log file format."""
        return 'json'

    data: 'List[Model]'
    """:obj:`list` of :class:`~zlogging.model.Model`: Log records.

    The log records parsed as a :obj:`list` of :class:`~zlogging.model.Model` per line.
    """
