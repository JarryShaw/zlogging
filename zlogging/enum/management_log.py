# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Management::Log``."""

from zlogging._compat import enum


@enum.unique
class Level(enum.IntFlag):
    """Enum: ``Management::Log::Level``.

    The controller/agent log supports four different log levels.

    See Also:
        `policy/frameworks/management/log.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/management/log.zeek.html#type-Management::Log::Level>`__

    """

    _ignore_ = 'Level _'
    Level = vars()

    DEBUG = enum.auto()

    INFO = enum.auto()

    WARNING = enum.auto()

    ERROR = enum.auto()
