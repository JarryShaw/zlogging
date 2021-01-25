# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
"""Namespace: ``Tunnel``."""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """Enum: ``Tunnel::Type``.

    See Also:
        `base/bif/types.bif.zeek`_

    .. _base/bif/types.bif.zeek: https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-Tunnel::Type

    """

    _ignore_ = 'Type _'
    Type = vars()

    Type['NONE'] = enum.auto()

    Type['IP'] = enum.auto()

    Type['AYIYA'] = enum.auto()

    Type['TEREDO'] = enum.auto()

    Type['SOCKS'] = enum.auto()

    Type['GTPv1'] = enum.auto()

    Type['HTTP'] = enum.auto()

    Type['GRE'] = enum.auto()

    Type['VXLAN'] = enum.auto()


@enum.unique
class Action(enum.IntFlag):
    """Enum: ``Tunnel::Action``.

    Types of interesting activity that can occur with a tunnel.

    See Also:
        `base/frameworks/tunnels/main.zeek`_

    .. _base/frameworks/tunnels/main.zeek: https://docs.zeek.org/en/stable/scripts/base/frameworks/tunnels/main.zeek.html#type-Tunnel::Action

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: A new tunnel (encapsulating “connection”) has been seen.
    Action['DISCOVER'] = enum.auto()

    #: A tunnel connection has closed.
    Action['CLOSE'] = enum.auto()

    #: No new connections over a tunnel happened in the amount of
    #: time indicated by Tunnel::expiration\_interval.
    Action['EXPIRE'] = enum.auto()
