# -*- coding: utf-8 -*-
"""Namespace: ProtocolDetector.

:module: zlogging.enum.ProtocolDetector
"""

from zlogging._compat import enum


@enum.unique
class dir(enum.IntFlag):
    """c.f. `policy/frameworks/dpd/detect-protocols.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/dpd/detect-protocols.zeek.html>`__"""

    _ignore_ = 'dir _'
    dir = vars()

    #: :currentmodule: zlogging.enum.ProtocolDetector
    dir['NONE'] = enum.auto()

    #: :currentmodule: zlogging.enum.ProtocolDetector
    dir['INCOMING'] = enum.auto()

    #: :currentmodule: zlogging.enum.ProtocolDetector
    dir['OUTGOING'] = enum.auto()

    #: :currentmodule: zlogging.enum.ProtocolDetector
    dir['BOTH'] = enum.auto()
