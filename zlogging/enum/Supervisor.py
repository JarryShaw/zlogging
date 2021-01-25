# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
"""Namespace: ``Supervisor``."""

from zlogging._compat import enum


@enum.unique
class ClusterRole(enum.IntFlag):
    """Enum: ``Supervisor::ClusterRole``.

    The role a supervised-node will play in Zeek’s Cluster Framework.

    See Also:
        `base/frameworks/supervisor/api.zeek`_

    .. _base/frameworks/supervisor/api.zeek: https://docs.zeek.org/en/stable/scripts/base/frameworks/supervisor/api.zeek.html#type-Supervisor::ClusterRole

    """

    _ignore_ = 'ClusterRole _'
    ClusterRole = vars()

    ClusterRole['NONE'] = enum.auto()

    ClusterRole['LOGGER'] = enum.auto()

    ClusterRole['MANAGER'] = enum.auto()

    ClusterRole['PROXY'] = enum.auto()

    ClusterRole['WORKER'] = enum.auto()
