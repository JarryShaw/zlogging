# -*- coding: utf-8 -*-
"""Namespace: Tunnel."""

import enum


@enum.unique
class Type(enum.IntFlag):
    """
    c.f. {html_path}
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
    """Types of interesting activity that can occur with a tunnel.

    
    c.f. {html_path}
    """

    _ignore_ = 'Action _'
    Action = vars()

    # A new tunnel (encapsulating “connection”) has been seen.
    Action['DISCOVER'] = enum.auto()

    # A tunnel connection has closed.
    Action['CLOSE'] = enum.auto()

    # No new connections over a tunnel happened in the amount of
    # time indicated by Tunnel::expiration_interval.
    Action['EXPIRE'] = enum.auto()
