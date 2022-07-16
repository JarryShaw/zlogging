# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``SOCKS``."""

from zlogging._compat import enum


@enum.unique
class RequestType(enum.IntFlag):
    """Enum: ``SOCKS::RequestType``.

    See Also:
        `base/protocols/socks/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/socks/consts.zeek.html#type-SOCKS::RequestType>`__

    """

    _ignore_ = 'RequestType _'
    RequestType = vars()

    CONNECTION = enum.auto()

    PORT = enum.auto()

    UDP_ASSOCIATE = enum.auto()
