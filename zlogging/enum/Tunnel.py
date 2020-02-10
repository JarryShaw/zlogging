# -*- coding: utf-8 -*-
"""Namespace: Tunnel.

:module: zlogging.enum.Tunnel
"""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'Type _'
    Type = vars()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['NONE'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['IP'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['AYIYA'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['TEREDO'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['SOCKS'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['GTPv1'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['HTTP'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['GRE'] = enum.auto()

    #: :currentmodule: zlogging.enum.Tunnel
    Type['VXLAN'] = enum.auto()


@enum.unique
class Action(enum.IntFlag):
    """Types of interesting activity that can occur with a tunnel.

    c.f. `base/frameworks/tunnels/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/tunnels/main.zeek.html>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: A new tunnel (encapsulating “connection”) has been seen.
    #: :currentmodule: zlogging.enum.Tunnel
    Action['DISCOVER'] = enum.auto()

    #: A tunnel connection has closed.
    #: :currentmodule: zlogging.enum.Tunnel
    Action['CLOSE'] = enum.auto()

    #: No new connections over a tunnel happened in the amount of
    #: time indicated by Tunnel::expiration_interval.
    #: :currentmodule: zlogging.enum.Tunnel
    Action['EXPIRE'] = enum.auto()
