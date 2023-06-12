# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Broker``."""

from zlogging._compat import enum


@enum.unique
class BrokerProtocol(enum.IntFlag):
    """Enum: ``Broker::BrokerProtocol``.

    See Also:
        `base/bif/comm.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/comm.bif.zeek.html#type-Broker::BrokerProtocol>`__

    """

    _ignore_ = 'BrokerProtocol _'
    BrokerProtocol = vars()

    NATIVE = enum.auto()

    WEBSOCKET = enum.auto()


@enum.unique
class DataType(enum.IntFlag):
    """Enum: ``Broker::DataType``.

    Enumerates the possible types that ``Broker::Data`` may be in terms of Zeek data types.

    See Also:
        `base/bif/data.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/data.bif.zeek.html#type-Broker::DataType>`__

    """

    _ignore_ = 'DataType _'
    DataType = vars()

    NONE = enum.auto()

    BOOL = enum.auto()

    INT = enum.auto()

    COUNT = enum.auto()

    DOUBLE = enum.auto()

    STRING = enum.auto()

    ADDR = enum.auto()

    SUBNET = enum.auto()

    PORT = enum.auto()

    TIME = enum.auto()

    INTERVAL = enum.auto()

    ENUM = enum.auto()

    SET = enum.auto()

    TABLE = enum.auto()

    VECTOR = enum.auto()


@enum.unique
class Type(enum.IntFlag):
    """Enum: ``Broker::Type``.

    The type of a Broker activity being logged.

    See Also:
        `base/frameworks/broker/log.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/log.zeek.html#type-Broker::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: An informational status update.
    STATUS = enum.auto()

    #: An error situation.
    ERROR = enum.auto()


@enum.unique
class ErrorCode(enum.IntFlag):
    """Enum: ``Broker::ErrorCode``.

    Enumerates the possible error types.

    See Also:
        `base/frameworks/broker/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/main.zeek.html#type-Broker::ErrorCode>`__

    """

    _ignore_ = 'ErrorCode _'
    ErrorCode = vars()

    #: (present if base/bif/comm.bif.zeek is loaded)
    NO_ERROR = enum.auto()

    #: The unspecified default error code.
    UNSPECIFIED = enum.auto()

    #: Version incompatibility.
    PEER_INCOMPATIBLE = enum.auto()

    #: Referenced peer does not exist.
    PEER_INVALID = enum.auto()

    #: Remote peer not listening.
    PEER_UNAVAILABLE = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    PEER_DISCONNECT_DURING_HANDSHAKE = enum.auto()

    #: A peering request timed out.
    PEER_TIMEOUT = enum.auto()

    #: Master with given name already exists.
    MASTER_EXISTS = enum.auto()

    #: Master with given name does not exist.
    NO_SUCH_MASTER = enum.auto()

    #: The given data store key does not exist.
    NO_SUCH_KEY = enum.auto()

    #: The store operation timed out.
    REQUEST_TIMEOUT = enum.auto()

    #: The operation expected a different type than provided.
    TYPE_CLASH = enum.auto()

    #: The data value cannot be used to carry out the desired operation.
    INVALID_DATA = enum.auto()

    #: The storage backend failed to execute the operation.
    BACKEND_FAILURE = enum.auto()

    #: The storage backend failed to execute the operation.
    STALE_DATA = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    CANNOT_OPEN_FILE = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    CANNOT_WRITE_FILE = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    INVALID_TOPIC_KEY = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    END_OF_FILE = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    INVALID_TAG = enum.auto()

    #: (present if base/bif/comm.bif.zeek is loaded)
    INVALID_STATUS = enum.auto()

    #: Catch-all for a CAF-level problem.
    CAF_ERROR = enum.auto()


@enum.unique
class PeerStatus(enum.IntFlag):
    """Enum: ``Broker::PeerStatus``.

    The possible states of a peer endpoint.

    See Also:
        `base/frameworks/broker/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/main.zeek.html#type-Broker::PeerStatus>`__

    """

    _ignore_ = 'PeerStatus _'
    PeerStatus = vars()

    #: The peering process is initiated.
    INITIALIZING = enum.auto()

    #: Connection establishment in process.
    CONNECTING = enum.auto()

    #: Connection established, peering pending.
    CONNECTED = enum.auto()

    #: Successfully peered.
    PEERED = enum.auto()

    #: Connection to remote peer lost.
    DISCONNECTED = enum.auto()

    #: Reconnecting to peer after a lost connection.
    RECONNECTING = enum.auto()


@enum.unique
class BackendType(enum.IntFlag):
    """Enum: ``Broker::BackendType``.

    Enumerates the possible storage backends.

    See Also:
        `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::BackendType>`__

    """

    _ignore_ = 'BackendType _'
    BackendType = vars()

    MEMORY = enum.auto()

    SQLITE = enum.auto()


@enum.unique
class QueryStatus(enum.IntFlag):
    """Enum: ``Broker::QueryStatus``.

    Whether a data store query could be completed or not.

    See Also:
        `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::QueryStatus>`__

    """

    _ignore_ = 'QueryStatus _'
    QueryStatus = vars()

    SUCCESS = enum.auto()

    FAILURE = enum.auto()


@enum.unique
class SQLiteFailureMode(enum.IntFlag):
    """Enum: ``Broker::SQLiteFailureMode``.

    Behavior when the SQLite database file is found to be corrupt or otherwise fails to open or
    initialize.

    See Also:
        `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::SQLiteFailureMode>`__

    """

    _ignore_ = 'SQLiteFailureMode _'
    SQLiteFailureMode = vars()

    #: Fail during initialization.
    SQLITE_FAILURE_MODE_FAIL = enum.auto()

    #: Attempt to delete the database file and retry.
    SQLITE_FAILURE_MODE_DELETE = enum.auto()


@enum.unique
class SQLiteJournalMode(enum.IntFlag):
    """Enum: ``Broker::SQLiteJournalMode``.

    Values supported for SQLite’s PRAGMA journal_mode statement.

    See Also:
        `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::SQLiteJournalMode>`__

    """

    _ignore_ = 'SQLiteJournalMode _'
    SQLiteJournalMode = vars()

    SQLITE_JOURNAL_MODE_DELETE = enum.auto()

    SQLITE_JOURNAL_MODE_WAL = enum.auto()


@enum.unique
class SQLiteSynchronous(enum.IntFlag):
    """Enum: ``Broker::SQLiteSynchronous``.

    Values supported for SQLite’s PRAGMA synchronous statement.

    See Also:
        `base/frameworks/broker/store.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/broker/store.zeek.html#type-Broker::SQLiteSynchronous>`__

    """

    _ignore_ = 'SQLiteSynchronous _'
    SQLiteSynchronous = vars()

    SQLITE_SYNCHRONOUS_OFF = enum.auto()

    SQLITE_SYNCHRONOUS_NORMAL = enum.auto()

    SQLITE_SYNCHRONOUS_FULL = enum.auto()

    SQLITE_SYNCHRONOUS_EXTRA = enum.auto()
