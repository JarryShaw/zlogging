# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``JSON``."""

from zlogging._compat import enum


@enum.unique
class TimestampFormat(enum.IntFlag):
    """Enum: ``JSON::TimestampFormat``.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-JSON::TimestampFormat>`__

    """

    _ignore_ = 'TimestampFormat _'
    TimestampFormat = vars()

    #: Timestamps will be formatted as UNIX epoch doubles.  This is
    #: the format that Zeek typically writes out timestamps.
    TS_EPOCH = enum.auto()

    #: Timestamps will be formatted as unsigned integers that
    #: represent the number of milliseconds since the UNIX
    #: epoch.
    TS_MILLIS = enum.auto()

    #: Timestamps will be formatted in the ISO8601 DateTime format.
    #: Subseconds are also included which isn’t actually part of the
    #: standard but most consumers that parse ISO8601 seem to be able
    #: to cope with that.
    TS_ISO8601 = enum.auto()
