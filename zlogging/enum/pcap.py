# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Pcap``."""

from zlogging._compat import enum


@enum.unique
class filter_state(enum.IntFlag):
    """Enum: ``Pcap::filter_state``.

    The state of the compilation for a pcap filter.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-Pcap::filter_state>`__

    """

    _ignore_ = 'filter_state _'
    filter_state = vars()

    ok = enum.auto()

    fatal = enum.auto()

    warning = enum.auto()
