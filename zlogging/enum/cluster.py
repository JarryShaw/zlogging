# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Cluster``."""

from zlogging._compat import enum


@enum.unique
class NodeType(enum.IntFlag):
    """Enum: ``Cluster::NodeType``.

    Types of nodes that are allowed to participate in the cluster configuration.

    See Also:
        `base/frameworks/cluster/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/cluster/main.zeek.html#type-Cluster::NodeType>`__

    """

    _ignore_ = 'NodeType _'
    NodeType = vars()

    #: A dummy node type indicating the local node is not operating
    #: within a cluster.
    NONE = enum.auto()

    #: A node type which is allowed to view/manipulate the configuration
    #: of other nodes in the cluster.
    CONTROL = enum.auto()

    #: A node type responsible for log management.
    LOGGER = enum.auto()

    #: A node type responsible for policy management.
    MANAGER = enum.auto()

    #: A node type for relaying worker node communication and synchronizing
    #: worker node state.
    PROXY = enum.auto()

    #: The node type doing all the actual traffic analysis.
    WORKER = enum.auto()


@enum.unique
class BackendTag(enum.IntFlag):
    """Enum: ``Cluster::BackendTag``.

    See Also:
        `base/frameworks/cluster/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/cluster/main.zeek.html#type-Cluster::BackendTag>`__

    """

    _ignore_ = 'BackendTag _'
    BackendTag = vars()

    CLUSTER_BACKEND_BROKER = enum.auto()

    CLUSTER_BACKEND_ZEROMQ = enum.auto()


@enum.unique
class EventSerializerTag(enum.IntFlag):
    """Enum: ``Cluster::EventSerializerTag``.

    See Also:
        `base/frameworks/cluster/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/cluster/main.zeek.html#type-Cluster::EventSerializerTag>`__

    """

    _ignore_ = 'EventSerializerTag _'
    EventSerializerTag = vars()

    EVENT_SERIALIZER_BROKER_BIN_V1 = enum.auto()

    EVENT_SERIALIZER_BROKER_JSON_V1 = enum.auto()


@enum.unique
class LogSerializerTag(enum.IntFlag):
    """Enum: ``Cluster::LogSerializerTag``.

    See Also:
        `base/frameworks/cluster/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/cluster/main.zeek.html#type-Cluster::LogSerializerTag>`__

    """

    _ignore_ = 'LogSerializerTag _'
    LogSerializerTag = vars()

    LOG_SERIALIZER_ZEEK_BIN_V1 = enum.auto()
