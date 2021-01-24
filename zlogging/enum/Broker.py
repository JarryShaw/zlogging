# -*- coding: utf-8 -*-
"""Namespace: ``Broker``."""

from zlogging._compat import enum


@enum.unique
class DataType(enum.IntFlag):
    """Enumerates the possible types that Broker::Data may be in
    terms of Zeek data types.

    c.f. `base/bif/data.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/data.bif.zeek.html#type-Broker::DataType>`__

    """

    _ignore_ = 'DataType _'
    DataType = vars()

    DataType['NONE'] = enum.auto()

    DataType['BOOL'] = enum.auto()

    DataType['INT'] = enum.auto()

    DataType['COUNT'] = enum.auto()

    DataType['DOUBLE'] = enum.auto()

    DataType['STRING'] = enum.auto()

    DataType['ADDR'] = enum.auto()

    DataType['SUBNET'] = enum.auto()

    DataType['PORT'] = enum.auto()

    DataType['TIME'] = enum.auto()

    DataType['INTERVAL'] = enum.auto()

    DataType['ENUM'] = enum.auto()

    DataType['SET'] = enum.auto()

    DataType['TABLE'] = enum.auto()

    DataType['VECTOR'] = enum.auto()


@enum.unique
class Type(enum.IntFlag):
    """The type of a Broker activity being logged.

    c.f. `base/frameworks/broker/log.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/log.zeek.html#type-Broker::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: An informational status update.
    Type['STATUS'] = enum.auto()

    #: An error situation.
    Type['ERROR'] = enum.auto()


@enum.unique
class ErrorCode(enum.IntFlag):
    """Enumerates the possible error types.

    c.f. `base/frameworks/broker/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/main.zeek.html#type-Broker::ErrorCode>`__

    """

    _ignore_ = 'ErrorCode _'
    ErrorCode = vars()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['NO_ERROR'] = enum.auto()

    #: The unspecified default error code.
    ErrorCode['UNSPECIFIED'] = enum.auto()

    #: Version incompatibility.
    ErrorCode['PEER_INCOMPATIBLE'] = enum.auto()

    #: Referenced peer does not exist.
    ErrorCode['PEER_INVALID'] = enum.auto()

    #: Remote peer not listening.
    ErrorCode['PEER_UNAVAILABLE'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['PEER_DISCONNECT_DURING_HANDSHAKE'] = enum.auto()

    #: A peering request timed out.
    ErrorCode['PEER_TIMEOUT'] = enum.auto()

    #: Master with given name already exists.
    ErrorCode['MASTER_EXISTS'] = enum.auto()

    #: Master with given name does not exist.
    ErrorCode['NO_SUCH_MASTER'] = enum.auto()

    #: The given data store key does not exist.
    ErrorCode['NO_SUCH_KEY'] = enum.auto()

    #: The store operation timed out.
    ErrorCode['REQUEST_TIMEOUT'] = enum.auto()

    #: The operation expected a different type than provided.
    ErrorCode['TYPE_CLASH'] = enum.auto()

    #: The data value cannot be used to carry out the desired operation.
    ErrorCode['INVALID_DATA'] = enum.auto()

    #: The storage backend failed to execute the operation.
    ErrorCode['BACKEND_FAILURE'] = enum.auto()

    #: The storage backend failed to execute the operation.
    ErrorCode['STALE_DATA'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['CANNOT_OPEN_FILE'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['CANNOT_WRITE_FILE'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['INVALID_TOPIC_KEY'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['END_OF_FILE'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['INVALID_TAG'] = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    ErrorCode['INVALID_STATUS'] = enum.auto()

    #: Catch-all for a CAF-level problem.
    ErrorCode['CAF_ERROR'] = enum.auto()


@enum.unique
class PeerStatus(enum.IntFlag):
    """The possible states of a peer endpoint.

    c.f. `base/frameworks/broker/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/main.zeek.html#type-Broker::PeerStatus>`__

    """

    _ignore_ = 'PeerStatus _'
    PeerStatus = vars()

    #: The peering process is initiated.
    PeerStatus['INITIALIZING'] = enum.auto()

    #: Connection establishment in process.
    PeerStatus['CONNECTING'] = enum.auto()

    #: Connection established, peering pending.
    PeerStatus['CONNECTED'] = enum.auto()

    #: Successfully peered.
    PeerStatus['PEERED'] = enum.auto()

    #: Connection to remote peer lost.
    PeerStatus['DISCONNECTED'] = enum.auto()

    #: Reconnecting to peer after a lost connection.
    PeerStatus['RECONNECTING'] = enum.auto()


@enum.unique
class BackendType(enum.IntFlag):
    """Enumerates the possible storage backends.

    c.f. `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::BackendType>`__

    """

    _ignore_ = 'BackendType _'
    BackendType = vars()

    BackendType['MEMORY'] = enum.auto()

    BackendType['SQLITE'] = enum.auto()

    BackendType['ROCKSDB'] = enum.auto()


@enum.unique
class QueryStatus(enum.IntFlag):
    """Whether a data store query could be completed or not.

    c.f. `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::QueryStatus>`__

    """

    _ignore_ = 'QueryStatus _'
    QueryStatus = vars()

    QueryStatus['SUCCESS'] = enum.auto()

    QueryStatus['FAILURE'] = enum.auto()
