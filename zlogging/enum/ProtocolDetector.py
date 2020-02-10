# -*- coding: utf-8 -*-
"""Namespace: ``ProtocolDetector``."""

from zlogging._compat import enum


@enum.unique
class dir(enum.IntFlag):
    """c.f. `policy/frameworks/dpd/detect-protocols.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/dpd/detect-protocols.zeek.html#type-ProtocolDetector::dir>`__"""

    _ignore_ = 'dir _'
    dir = vars()

    dir['NONE'] = enum.auto()

    dir['INCOMING'] = enum.auto()

    dir['OUTGOING'] = enum.auto()

    dir['BOTH'] = enum.auto()
