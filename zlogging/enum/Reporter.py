# -*- coding: utf-8 -*-
"""Namespace: Reporter."""

import enum


@enum.unique
class Level(enum.IntFlag):
    """
    c.f. {html_path}
    """

    _ignore_ = 'Level _'
    Level = vars()

    Level['INFO'] = enum.auto()

    Level['WARNING'] = enum.auto()

    Level['ERROR'] = enum.auto()
