# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``ProtocolDetector``."""

from zlogging._compat import enum


@enum.unique
class dir(enum.IntFlag):
    """Enum: ``ProtocolDetector::dir``.

    See Also:
        `policy/frameworks/dpd/detect-protocols.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/dpd/detect-protocols.zeek.html#type-ProtocolDetector::dir>`__

    """

    _ignore_ = 'dir _'
    dir = vars()

    NONE = enum.auto()

    INCOMING = enum.auto()

    OUTGOING = enum.auto()

    BOTH = enum.auto()
