# -*- coding: utf-8 -*-
"""Namespace: Broker."""

import enum


@enum.unique
class DataType(enum.IntFlag):
    """Enumerates the possible types that Broker::Data may be in
    terms of Zeek data types.

    
    c.f. {html_path}
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

    
    c.f. {html_path}
    """

    _ignore_ = 'Type _'
    Type = vars()

    # An informational status update.
    Type['STATUS'] = enum.auto()

    # An error situation.
    Type['ERROR'] = enum.auto()


@enum.unique
class ErrorCode(enum.IntFlag):
    """Enumerates the possible error types.

    
    c.f. {html_path}
    """

    _ignore_ = 'ErrorCode _'
    ErrorCode = vars()

    # The unspecified default error code.
    ErrorCode['UNSPECIFIED'] = enum.auto()

    # Version incompatibility.
    ErrorCode['PEER_INCOMPATIBLE'] = enum.auto()

    # Referenced peer does not exist.
    ErrorCode['PEER_INVALID'] = enum.auto()

    # Remote peer not listening.
    ErrorCode['PEER_UNAVAILABLE'] = enum.auto()

    # A peering request timed out.
    ErrorCode['PEER_TIMEOUT'] = enum.auto()

    # Master with given name already exists.
    ErrorCode['MASTER_EXISTS'] = enum.auto()

    # Master with given name does not exist.
    ErrorCode['NO_SUCH_MASTER'] = enum.auto()

    # The given data store key does not exist.
    ErrorCode['NO_SUCH_KEY'] = enum.auto()

    # The store operation timed out.
    ErrorCode['REQUEST_TIMEOUT'] = enum.auto()

    # The operation expected a different type than provided.
    ErrorCode['TYPE_CLASH'] = enum.auto()

    # The data value cannot be used to carry out the desired operation.
    ErrorCode['INVALID_DATA'] = enum.auto()

    # The storage backend failed to execute the operation.
    ErrorCode['BACKEND_FAILURE'] = enum.auto()

    # The storage backend failed to execute the operation.
    ErrorCode['STALE_DATA'] = enum.auto()

    # Catch-all for a CAF-level problem.
    ErrorCode['CAF_ERROR'] = enum.auto()


@enum.unique
class PeerStatus(enum.IntFlag):
    """The possible states of a peer endpoint.

    
    c.f. {html_path}
    """

    _ignore_ = 'PeerStatus _'
    PeerStatus = vars()

    # The peering process is initiated.
    PeerStatus['INITIALIZING'] = enum.auto()

    # Connection establishment in process.
    PeerStatus['CONNECTING'] = enum.auto()

    # Connection established, peering pending.
    PeerStatus['CONNECTED'] = enum.auto()

    # Successfully peered.
    PeerStatus['PEERED'] = enum.auto()

    # Connection to remote peer lost.
    PeerStatus['DISCONNECTED'] = enum.auto()

    # Reconnecting to peer after a lost connection.
    PeerStatus['RECONNECTING'] = enum.auto()


@enum.unique
class BackendType(enum.IntFlag):
    """Enumerates the possible storage backends.

    
    c.f. {html_path}
    """

    _ignore_ = 'BackendType _'
    BackendType = vars()

    BackendType['MEMORY'] = enum.auto()

    BackendType['SQLITE'] = enum.auto()

    BackendType['ROCKSDB'] = enum.auto()


@enum.unique
class QueryStatus(enum.IntFlag):
    """Whether a data store query could be completed or not.

    
    c.f. {html_path}
    """

    _ignore_ = 'QueryStatus _'
    QueryStatus = vars()

    QueryStatus['SUCCESS'] = enum.auto()

    QueryStatus['FAILURE'] = enum.auto()
