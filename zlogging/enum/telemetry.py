# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Telemetry``."""

from zlogging._compat import enum


@enum.unique
class MetricType(enum.IntFlag):
    """Enum: ``Telemetry::MetricType``.

    See Also:
        `base/bif/telemetry.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/telemetry.bif.zeek.html#type-Telemetry::MetricType>`__

    """

    _ignore_ = 'MetricType _'
    MetricType = vars()

    DOUBLE_COUNTER = enum.auto()

    INT_COUNTER = enum.auto()

    DOUBLE_GAUGE = enum.auto()

    INT_GAUGE = enum.auto()

    DOUBLE_HISTOGRAM = enum.auto()

    INT_HISTOGRAM = enum.auto()
