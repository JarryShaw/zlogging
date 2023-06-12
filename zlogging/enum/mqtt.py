# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``MQTT``."""

from zlogging._compat import enum


@enum.unique
class SubUnsub(enum.IntFlag):
    """Enum: ``MQTT::SubUnsub``.

    See Also:
        `base/protocols/mqtt/main.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/mqtt/main.zeek.html#type-MQTT::SubUnsub>`__

    """

    _ignore_ = 'SubUnsub _'
    SubUnsub = vars()

    SUBSCRIBE = enum.auto()

    UNSUBSCRIBE = enum.auto()
