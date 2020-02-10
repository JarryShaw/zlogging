# -*- coding: utf-8 -*-
"""Namespace: SumStats.

:module: zlogging.enum.SumStats
"""

from zlogging._compat import enum


@enum.unique
class Calculation(enum.IntFlag):
    """Type to represent the calculations that are available.  The calculations
    are all defined as plugins.

    c.f. `base/frameworks/sumstats/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/sumstats/main.zeek.html>`__

    """

    _ignore_ = 'Calculation _'
    Calculation = vars()

    #: :currentmodule: zlogging.enum.SumStats
    Calculation['PLACEHOLDER'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/average.zeek is loaded)
    #: Calculate the average of the values.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['AVERAGE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/hll_unique.zeek is loaded)
    #: Calculate the number of unique values.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['HLL_UNIQUE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/last.zeek is loaded)
    #: Keep last X observations in a queue.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['LAST'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/max.zeek is loaded)
    #: Find the maximum value.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['MAX'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/min.zeek is loaded)
    #: Find the minimum value.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['MIN'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/sample.zeek is loaded)
    #: Get uniquely distributed random samples from the observation
    #: stream.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['SAMPLE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/variance.zeek is loaded)
    #: Calculate the variance of the values.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['VARIANCE'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/std-dev.zeek is loaded)
    #: Calculate the standard deviation of the values.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['STD_DEV'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/sum.zeek is loaded)
    #: Calculate the sum of the values.  For string values,
    #: this will be the number of strings.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['SUM'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/topk.zeek is loaded)
    #: Keep a top-k list of values.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['TOPK'] = enum.auto()

    #: (present if base/frameworks/sumstats/plugins/unique.zeek is loaded)
    #: Calculate the number of unique values.
    #: :currentmodule: zlogging.enum.SumStats
    Calculation['UNIQUE'] = enum.auto()
