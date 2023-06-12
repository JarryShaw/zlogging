# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Tunnel``."""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """Enum: ``Tunnel::Type``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-Tunnel::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    NONE = enum.auto()

    IP = enum.auto()

    AYIYA = enum.auto()

    TEREDO = enum.auto()

    SOCKS = enum.auto()

    GTPv1 = enum.auto()

    HTTP = enum.auto()

    GRE = enum.auto()

    VXLAN = enum.auto()

    GENEVE = enum.auto()


@enum.unique
class Action(enum.IntFlag):
    """Enum: ``Tunnel::Action``.

    Types of interesting activity that can occur with a tunnel.

    See Also:
        `base/frameworks/tunnels/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/tunnels/main.zeek.html#type-Tunnel::Action>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: A new tunnel (encapsulating “connection”) has been seen.
    DISCOVER = enum.auto()

    #: A tunnel connection has closed.
    CLOSE = enum.auto()

    #: No new connections over a tunnel happened in the amount of
    #: time indicated by Tunnel::expiration\_interval.
    EXPIRE = enum.auto()
