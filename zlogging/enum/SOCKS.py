# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
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

    RequestType['CONNECTION'] = enum.auto()

    RequestType['PORT'] = enum.auto()

    RequestType['UDP_ASSOCIATE'] = enum.auto()
