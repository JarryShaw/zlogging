# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``SumStats``."""

from zlogging._compat import enum


@enum.unique
class Calculation(enum.IntFlag):
    """Enum: ``SumStats::Calculation``.

    Type to represent the calculations that are available. The calculations are all defined as plugins.

    See Also:
        `base/frameworks/sumstats/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/sumstats/main.zeek.html#type-SumStats::Calculation>`__

    """

    _ignore_ = 'Calculation _'
    Calculation = vars()

    PLACEHOLDER = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/average.zeek is loaded)
    #: Calculate the average of the values.
    AVERAGE = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/hll\_unique.zeek is loaded)
    #: Calculate the number of unique values.
    HLL_UNIQUE = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/last.zeek is loaded)
    #: Keep last X observations in a queue.
    LAST = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/max.zeek is loaded)
    #: Find the maximum value.
    MAX = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/min.zeek is loaded)
    #: Find the minimum value.
    MIN = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/sample.zeek is loaded)
    #: Get uniquely distributed random samples from the observation
    #: stream.
    SAMPLE = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/variance.zeek is loaded)
    #: Calculate the variance of the values.
    VARIANCE = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/std-dev.zeek is loaded)
    #: Calculate the standard deviation of the values.
    STD_DEV = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/sum.zeek is loaded)
    #: Calculate the sum of the values.  For string values,
    #: this will be the number of strings.
    SUM = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/topk.zeek is loaded)
    #: Keep a top-k list of values.
    TOPK = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/unique.zeek is loaded)
    #: Calculate the number of unique values.
    UNIQUE = enum.auto()
