# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Telemetry``."""

from zlogging._compat import enum


@enum.unique
class MetricType(enum.IntFlag):
    """Enum: ``Telemetry::MetricType``.

    An enum that specifies which type of metric you’re operating on.

    See Also:
        `base/bif/telemetry_types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/telemetry_types.bif.zeek.html#type-Telemetry::MetricType>`__

    """

    _ignore_ = 'MetricType _'
    MetricType = vars()

    #: Counters track entities that increment over time.
    COUNTER = enum.auto()

    #: Gauges track entities that fluctuate over time.
    GAUGE = enum.auto()

    #: Histograms group observations into predefined bins.
    HISTOGRAM = enum.auto()
