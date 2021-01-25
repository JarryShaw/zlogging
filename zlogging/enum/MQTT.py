# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
"""Namespace: ``MQTT``."""

from zlogging._compat import enum


@enum.unique
class SubUnsub(enum.IntFlag):
    """Enum: ``MQTT::SubUnsub``.

    See Also:
        `policy/protocols/mqtt/main.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::SubUnsub>`__

    """

    _ignore_ = 'SubUnsub _'
    SubUnsub = vars()

    SubUnsub['SUBSCRIBE'] = enum.auto()

    SubUnsub['UNSUBSCRIBE'] = enum.auto()
