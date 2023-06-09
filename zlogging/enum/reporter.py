# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Reporter``."""

from zlogging._compat import enum


@enum.unique
class Level(enum.IntFlag):
    """Enum: ``Reporter::Level``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-Reporter::Level>`__

    """

    _ignore_ = 'Level _'
    Level = vars()

    INFO = enum.auto()

    WARNING = enum.auto()

    ERROR = enum.auto()
