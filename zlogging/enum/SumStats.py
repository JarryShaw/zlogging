# -*- coding: utf-8 -*-
"""Namespace: ``SumStats``."""

from zlogging._compat import enum


@enum.unique
class Calculation(enum.IntFlag):
    """Type to represent the calculations that are available.  The calculations
    are all defined as plugins.

    c.f. `base/frameworks/sumstats/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/sumstats/main.zeek.html#type-SumStats::Calculation>`__

    """

    _ignore_ = 'Calculation _'
    Calculation = vars()

    Calculation['PLACEHOLDER'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/average.zeek is loaded)
    #: Calculate the average of the values.
    Calculation['AVERAGE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/hll\_unique.zeek is loaded)
    #: Calculate the number of unique values.
    Calculation['HLL_UNIQUE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/last.zeek is loaded)
    #: Keep last X observations in a queue.
    Calculation['LAST'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/max.zeek is loaded)
    #: Find the maximum value.
    Calculation['MAX'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/min.zeek is loaded)
    #: Find the minimum value.
    Calculation['MIN'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/sample.zeek is loaded)
    #: Get uniquely distributed random samples from the observation
    #: stream.
    Calculation['SAMPLE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/variance.zeek is loaded)
    #: Calculate the variance of the values.
    Calculation['VARIANCE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/std-dev.zeek is loaded)
    #: Calculate the standard deviation of the values.
    Calculation['STD_DEV'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/sum.zeek is loaded)
    #: Calculate the sum of the values.  For string values,
    #: this will be the number of strings.
    Calculation['SUM'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/topk.zeek is loaded)
    #: Keep a top-k list of values.
    Calculation['TOPK'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/unique.zeek is loaded)
    #: Calculate the number of unique values.
    Calculation['UNIQUE'] = enum.auto()
