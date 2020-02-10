# -*- coding: utf-8 -*-
"""Namespace: ``Cluster``."""

from zlogging._compat import enum


@enum.unique
class NodeType(enum.IntFlag):
    """Types of nodes that are allowed to participate in the cluster
    configuration.

    c.f. `base/frameworks/cluster/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/cluster/main.zeek.html#type-Cluster::NodeType>`__

    """

    _ignore_ = 'NodeType _'
    NodeType = vars()

    #: A dummy node type indicating the local node is not operating
    #: within a cluster.
    NodeType['NONE'] = enum.auto()

    #: A node type which is allowed to view/manipulate the configuration
    #: of other nodes in the cluster.
    NodeType['CONTROL'] = enum.auto()

    #: A node type responsible for log management.
    NodeType['LOGGER'] = enum.auto()

    #: A node type responsible for policy management.
    NodeType['MANAGER'] = enum.auto()

    #: A node type for relaying worker node communication and synchronizing
    #: worker node state.
    NodeType['PROXY'] = enum.auto()

    #: The node type doing all the actual traffic analysis.
    NodeType['WORKER'] = enum.auto()

    #: A node acting as a traffic recorder using the
    #: Time Machine
    #: software.
    NodeType['TIME_MACHINE'] = enum.auto()
