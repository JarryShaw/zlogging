# -*- coding: utf-8 -*-
"""Namespace: ProtocolDetector."""

import enum


@enum.unique
class dir(enum.IntFlag):
    """
    c.f. {html_path}
    """

    _ignore_ = 'dir _'
    dir = vars()

    dir['NONE'] = enum.auto()

    dir['INCOMING'] = enum.auto()

    dir['OUTGOING'] = enum.auto()

    dir['BOTH'] = enum.auto()
