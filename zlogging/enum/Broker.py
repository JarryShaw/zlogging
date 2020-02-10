# -*- coding: utf-8 -*-
"""Namespace: Broker.

:module: zlogging.enum.Broker
"""

from zlogging._compat import enum


@enum.unique
class DataType(enum.IntFlag):
    """Enumerates the possible types that Broker::Data may be in
    terms of Zeek data types.

    c.f. `base/bif/data.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/data.bif.zeek.html>`__

    """

    _ignore_ = 'DataType _'
    DataType = vars()

    #: :currentmodule: zlogging.enum.Broker
    DataType['NONE'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['BOOL'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['INT'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['COUNT'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['DOUBLE'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['STRING'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['ADDR'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['SUBNET'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['PORT'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['TIME'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['INTERVAL'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['ENUM'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['SET'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['TABLE'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    DataType['VECTOR'] = enum.auto()


@enum.unique
class Type(enum.IntFlag):
    """The type of a Broker activity being logged.

    c.f. `base/frameworks/broker/log.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/log.zeek.html>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: An informational status update.
    #: :currentmodule: zlogging.enum.Broker
    Type['STATUS'] = enum.auto()

    #: An error situation.
    #: :currentmodule: zlogging.enum.Broker
    Type['ERROR'] = enum.auto()


@enum.unique
class ErrorCode(enum.IntFlag):
    """Enumerates the possible error types.

    c.f. `base/frameworks/broker/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/main.zeek.html>`__

    """

    _ignore_ = 'ErrorCode _'
    ErrorCode = vars()

    #: The unspecified default error code.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['UNSPECIFIED'] = enum.auto()

    #: Version incompatibility.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['PEER_INCOMPATIBLE'] = enum.auto()

    #: Referenced peer does not exist.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['PEER_INVALID'] = enum.auto()

    #: Remote peer not listening.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['PEER_UNAVAILABLE'] = enum.auto()

    #: A peering request timed out.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['PEER_TIMEOUT'] = enum.auto()

    #: Master with given name already exists.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['MASTER_EXISTS'] = enum.auto()

    #: Master with given name does not exist.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['NO_SUCH_MASTER'] = enum.auto()

    #: The given data store key does not exist.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['NO_SUCH_KEY'] = enum.auto()

    #: The store operation timed out.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['REQUEST_TIMEOUT'] = enum.auto()

    #: The operation expected a different type than provided.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['TYPE_CLASH'] = enum.auto()

    #: The data value cannot be used to carry out the desired operation.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['INVALID_DATA'] = enum.auto()

    #: The storage backend failed to execute the operation.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['BACKEND_FAILURE'] = enum.auto()

    #: The storage backend failed to execute the operation.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['STALE_DATA'] = enum.auto()

    #: Catch-all for a CAF-level problem.
    #: :currentmodule: zlogging.enum.Broker
    ErrorCode['CAF_ERROR'] = enum.auto()


@enum.unique
class PeerStatus(enum.IntFlag):
    """The possible states of a peer endpoint.

    c.f. `base/frameworks/broker/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/main.zeek.html>`__

    """

    _ignore_ = 'PeerStatus _'
    PeerStatus = vars()

    #: The peering process is initiated.
    #: :currentmodule: zlogging.enum.Broker
    PeerStatus['INITIALIZING'] = enum.auto()

    #: Connection establishment in process.
    #: :currentmodule: zlogging.enum.Broker
    PeerStatus['CONNECTING'] = enum.auto()

    #: Connection established, peering pending.
    #: :currentmodule: zlogging.enum.Broker
    PeerStatus['CONNECTED'] = enum.auto()

    #: Successfully peered.
    #: :currentmodule: zlogging.enum.Broker
    PeerStatus['PEERED'] = enum.auto()

    #: Connection to remote peer lost.
    #: :currentmodule: zlogging.enum.Broker
    PeerStatus['DISCONNECTED'] = enum.auto()

    #: Reconnecting to peer after a lost connection.
    #: :currentmodule: zlogging.enum.Broker
    PeerStatus['RECONNECTING'] = enum.auto()


@enum.unique
class BackendType(enum.IntFlag):
    """Enumerates the possible storage backends.

    c.f. `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html>`__

    """

    _ignore_ = 'BackendType _'
    BackendType = vars()

    #: :currentmodule: zlogging.enum.Broker
    BackendType['MEMORY'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    BackendType['SQLITE'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    BackendType['ROCKSDB'] = enum.auto()


@enum.unique
class QueryStatus(enum.IntFlag):
    """Whether a data store query could be completed or not.

    c.f. `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html>`__

    """

    _ignore_ = 'QueryStatus _'
    QueryStatus = vars()

    #: :currentmodule: zlogging.enum.Broker
    QueryStatus['SUCCESS'] = enum.auto()

    #: :currentmodule: zlogging.enum.Broker
    QueryStatus['FAILURE'] = enum.auto()
