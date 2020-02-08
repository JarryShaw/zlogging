# -*- coding: utf-8 -*-
"""Data models."""

import abc
import dataclasses

import blogging._typing as typing

__all__ = [
    'ASCIIInfo', 'JSONInfo'
]


class Info(metaclass=abc.ABCMeta):
    """Parsed log info."""

    @property
    @abc.abstractmethod
    def format(self):
        """str: Log file format."""


@dataclasses.dataclass(frozen=True)
class ASCIIInfo(Info):
    """Parsed log info for ASCII logs."""

    @property
    def format(self) -> str:
        """str: Log file format."""
        return 'ascii'

    path: typing.PathLike
    open: typing.DateTime
    close: typing.DateTime
    data: typing.DataFrame
    exit_with_error: bool


@dataclasses.dataclass(frozen=True)
class JSONInfo(Info):
    """Parsed log info for JSON logs."""

    @property
    def format(self) -> str:
        """str: Log file format."""
        return 'json'

    data: typing.DataFrame
