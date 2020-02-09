# -*- coding: utf-8 -*-
"""Namespace: MQTT."""

import enum


@enum.unique
class SubUnsub(enum.IntFlag):
    """
    c.f. {html_path}
    """

    _ignore_ = 'SubUnsub _'
    SubUnsub = vars()

    SubUnsub['SUBSCRIBE'] = enum.auto()

    SubUnsub['UNSUBSCRIBE'] = enum.auto()
