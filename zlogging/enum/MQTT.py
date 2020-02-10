# -*- coding: utf-8 -*-
"""Namespace: MQTT.

:module: zlogging.enum.MQTT
"""

from zlogging._compat import enum


@enum.unique
class SubUnsub(enum.IntFlag):
    """c.f. `policy/protocols/mqtt/main.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html>`__"""

    _ignore_ = 'SubUnsub _'
    SubUnsub = vars()

    #: :currentmodule: zlogging.enum.MQTT
    SubUnsub['SUBSCRIBE'] = enum.auto()

    #: :currentmodule: zlogging.enum.MQTT
    SubUnsub['UNSUBSCRIBE'] = enum.auto()
