# -*- coding: utf-8 -*-
"""Namespace: Reporter.

:module: zlogging.enum.Reporter
"""

from zlogging._compat import enum


@enum.unique
class Level(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'Level _'
    Level = vars()

    #: :currentmodule: zlogging.enum.Reporter
    Level['INFO'] = enum.auto()

    #: :currentmodule: zlogging.enum.Reporter
    Level['WARNING'] = enum.auto()

    #: :currentmodule: zlogging.enum.Reporter
    Level['ERROR'] = enum.auto()
