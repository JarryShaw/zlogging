# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``LoadBalancing``."""

from zlogging._compat import enum


@enum.unique
class Method(enum.IntFlag):
    """Enum: ``LoadBalancing::Method``.

    See Also:
        `policy/misc/load-balancing.zeek <https://docs.zeek.org/en/stable/scripts/policy/misc/load-balancing.zeek.html#type-LoadBalancing::Method>`__

    """

    _ignore_ = 'Method _'
    Method = vars()

    #: Apply BPF filters to each worker in a way that causes them to
    #: automatically flow balance traffic between them.
    AUTO_BPF = enum.auto()
