# -*- coding: utf-8 -*-
"""Namespace: ``Supervisor``."""

from zlogging._compat import enum


@enum.unique
class ClusterRole(enum.IntFlag):
    """The role a supervised-node will play in Zeek’s Cluster Framework.

    c.f. `base/frameworks/supervisor/api.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/supervisor/api.zeek.html#type-Supervisor::ClusterRole>`__

    """

    _ignore_ = 'ClusterRole _'
    ClusterRole = vars()

    ClusterRole['NONE'] = enum.auto()

    ClusterRole['LOGGER'] = enum.auto()

    ClusterRole['MANAGER'] = enum.auto()

    ClusterRole['PROXY'] = enum.auto()

    ClusterRole['WORKER'] = enum.auto()
