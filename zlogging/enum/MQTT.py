# -*- coding: utf-8 -*-
"""Namespace: ``MQTT``."""

from zlogging._compat import enum


@enum.unique
class SubUnsub(enum.IntFlag):
    """c.f. `policy/protocols/mqtt/main.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::SubUnsub>`__"""

    _ignore_ = 'SubUnsub _'
    SubUnsub = vars()

    SubUnsub['SUBSCRIBE'] = enum.auto()

    SubUnsub['UNSUBSCRIBE'] = enum.auto()
