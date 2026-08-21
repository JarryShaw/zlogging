# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Redis``."""

from zlogging._compat import enum


@enum.unique
class RedisCommand(enum.IntFlag):
    """Enum: ``Redis::RedisCommand``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-Redis::RedisCommand>`__

    """

    _ignore_ = 'RedisCommand _'
    RedisCommand = vars()

    RedisCommand_APPEND = enum.auto()

    RedisCommand_AUTH = enum.auto()

    RedisCommand_BITCOUNT = enum.auto()

    RedisCommand_BITFIELD = enum.auto()

    RedisCommand_BITFIELD_RO = enum.auto()

    RedisCommand_BITOP = enum.auto()

    RedisCommand_BITPOS = enum.auto()

    RedisCommand_BLMPOP = enum.auto()

    RedisCommand_BLPOP = enum.auto()

    RedisCommand_BRPOP = enum.auto()

    RedisCommand_CLIENT = enum.auto()

    RedisCommand_COPY = enum.auto()

    RedisCommand_DECR = enum.auto()

    RedisCommand_DECRBY = enum.auto()

    RedisCommand_DEL = enum.auto()

    RedisCommand_DUMP = enum.auto()

    RedisCommand_EXISTS = enum.auto()

    RedisCommand_EXPIRE = enum.auto()

    RedisCommand_EXPIREAT = enum.auto()

    RedisCommand_EXPIRETIME = enum.auto()

    RedisCommand_GET = enum.auto()

    RedisCommand_GETBIT = enum.auto()

    RedisCommand_GETDEL = enum.auto()

    RedisCommand_GETEX = enum.auto()

    RedisCommand_GETRANGE = enum.auto()

    RedisCommand_GETSET = enum.auto()

    RedisCommand_HDEL = enum.auto()

    RedisCommand_HELLO = enum.auto()

    RedisCommand_HGET = enum.auto()

    RedisCommand_HSET = enum.auto()

    RedisCommand_INCR = enum.auto()

    RedisCommand_INCRBY = enum.auto()

    RedisCommand_KEYS = enum.auto()

    RedisCommand_MGET = enum.auto()

    RedisCommand_MOVE = enum.auto()

    RedisCommand_MSET = enum.auto()

    RedisCommand_PERSIST = enum.auto()

    RedisCommand_PSUBSCRIBE = enum.auto()

    RedisCommand_PUNSUBSCRIBE = enum.auto()

    RedisCommand_QUIT = enum.auto()

    RedisCommand_RENAME = enum.auto()

    RedisCommand_RESET = enum.auto()

    RedisCommand_SET = enum.auto()

    RedisCommand_STRLEN = enum.auto()

    RedisCommand_SUBSCRIBE = enum.auto()

    RedisCommand_SSUBSCRIBE = enum.auto()

    RedisCommand_SUNSUBSCRIBE = enum.auto()

    RedisCommand_TTL = enum.auto()

    RedisCommand_TYPE = enum.auto()

    RedisCommand_UNSUBSCRIBE = enum.auto()

    RedisCommand_Undef = enum.auto()


@enum.unique
class ReplyType(enum.IntFlag):
    """Enum: ``Redis::ReplyType``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-Redis::ReplyType>`__

    """

    _ignore_ = 'ReplyType _'
    ReplyType = vars()

    ReplyType_Reply = enum.auto()

    ReplyType_Error = enum.auto()

    ReplyType_Push = enum.auto()

    ReplyType_Undef = enum.auto()
