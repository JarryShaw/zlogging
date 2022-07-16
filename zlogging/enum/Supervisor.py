# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Supervisor``."""

from zlogging._compat import enum


@enum.unique
class ClusterRole(enum.IntFlag):
    """Enum: ``Supervisor::ClusterRole``.

    The role a supervised-node will play in Zeek’s Cluster Framework.

    See Also:
        `base/frameworks/supervisor/api.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/supervisor/api.zeek.html#type-Supervisor::ClusterRole>`__

    """

    _ignore_ = 'ClusterRole _'
    ClusterRole = vars()

    NONE = enum.auto()

    LOGGER = enum.auto()

    MANAGER = enum.auto()

    PROXY = enum.auto()

    WORKER = enum.auto()
