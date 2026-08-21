# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``spicy``."""

from zlogging._compat import enum


@enum.unique
class AddressFamily(enum.IntFlag):
    """Enum: ``spicy::AddressFamily``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::AddressFamily>`__

    """

    _ignore_ = 'AddressFamily _'
    AddressFamily = vars()

    AddressFamily_IPv4 = enum.auto()

    AddressFamily_IPv6 = enum.auto()

    AddressFamily_Undef = enum.auto()


@enum.unique
class BitOrder(enum.IntFlag):
    """Enum: ``spicy::BitOrder``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::BitOrder>`__

    """

    _ignore_ = 'BitOrder _'
    BitOrder = vars()

    BitOrder_LSB0 = enum.auto()

    BitOrder_MSB0 = enum.auto()

    BitOrder_Undef = enum.auto()


@enum.unique
class ByteOrder(enum.IntFlag):
    """Enum: ``spicy::ByteOrder``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::ByteOrder>`__

    """

    _ignore_ = 'ByteOrder _'
    ByteOrder = vars()

    ByteOrder_Little = enum.auto()

    ByteOrder_Big = enum.auto()

    ByteOrder_Network = enum.auto()

    ByteOrder_Host = enum.auto()

    ByteOrder_Undef = enum.auto()


@enum.unique
class Charset(enum.IntFlag):
    """Enum: ``spicy::Charset``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::Charset>`__

    """

    _ignore_ = 'Charset _'
    Charset = vars()

    Charset_ASCII = enum.auto()

    Charset_UTF8 = enum.auto()

    Charset_UTF16LE = enum.auto()

    Charset_UTF16BE = enum.auto()

    Charset_Undef = enum.auto()


@enum.unique
class DecodeErrorStrategy(enum.IntFlag):
    """Enum: ``spicy::DecodeErrorStrategy``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::DecodeErrorStrategy>`__

    """

    _ignore_ = 'DecodeErrorStrategy _'
    DecodeErrorStrategy = vars()

    DecodeErrorStrategy_IGNORE = enum.auto()

    DecodeErrorStrategy_REPLACE = enum.auto()

    DecodeErrorStrategy_STRICT = enum.auto()

    DecodeErrorStrategy_Undef = enum.auto()


@enum.unique
class Protocol(enum.IntFlag):
    """Enum: ``spicy::Protocol``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::Protocol>`__

    """

    _ignore_ = 'Protocol _'
    Protocol = vars()

    Protocol_TCP = enum.auto()

    Protocol_UDP = enum.auto()

    Protocol_ICMP = enum.auto()

    Protocol_Undef = enum.auto()


@enum.unique
class RealType(enum.IntFlag):
    """Enum: ``spicy::RealType``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::RealType>`__

    """

    _ignore_ = 'RealType _'
    RealType = vars()

    RealType_IEEE754_Single = enum.auto()

    RealType_IEEE754_Double = enum.auto()

    RealType_Undef = enum.auto()


@enum.unique
class ReassemblerPolicy(enum.IntFlag):
    """Enum: ``spicy::ReassemblerPolicy``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::ReassemblerPolicy>`__

    """

    _ignore_ = 'ReassemblerPolicy _'
    ReassemblerPolicy = vars()

    ReassemblerPolicy_First = enum.auto()

    ReassemblerPolicy_Undef = enum.auto()


@enum.unique
class Side(enum.IntFlag):
    """Enum: ``spicy::Side``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::Side>`__

    """

    _ignore_ = 'Side _'
    Side = vars()

    Side_Left = enum.auto()

    Side_Right = enum.auto()

    Side_Both = enum.auto()

    Side_Undef = enum.auto()


@enum.unique
class Direction(enum.IntFlag):
    """Enum: ``spicy::Direction``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-spicy::Direction>`__

    """

    _ignore_ = 'Direction _'
    Direction = vars()

    Direction_Forward = enum.auto()

    Direction_Backward = enum.auto()

    Direction_Undef = enum.auto()
