# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Telemetry``."""

from zlogging._compat import enum


@enum.unique
class MetricType(enum.IntFlag):
    """Enum: ``Telemetry::MetricType``.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-Telemetry::MetricType>`__

    """

    _ignore_ = 'MetricType _'
    MetricType = vars()

    COUNTER = enum.auto()

    GAUGE = enum.auto()

    HISTOGRAM = enum.auto()
