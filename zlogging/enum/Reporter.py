# -*- coding: utf-8 -*-
"""Namespace: ``Reporter``."""

from zlogging._compat import enum


@enum.unique
class Level(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-Reporter::Level>`__"""

    _ignore_ = 'Level _'
    Level = vars()

    Level['INFO'] = enum.auto()

    Level['WARNING'] = enum.auto()

    Level['ERROR'] = enum.auto()
