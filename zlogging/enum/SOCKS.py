# -*- coding: utf-8 -*-
"""Namespace: SOCKS.

:module: zlogging.enum.SOCKS
"""

from zlogging._compat import enum


@enum.unique
class RequestType(enum.IntFlag):
    """c.f. `base/protocols/socks/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/socks/consts.zeek.html>`__"""

    _ignore_ = 'RequestType _'
    RequestType = vars()

    #: :currentmodule: zlogging.enum.SOCKS
    RequestType['CONNECTION'] = enum.auto()

    #: :currentmodule: zlogging.enum.SOCKS
    RequestType['PORT'] = enum.auto()

    #: :currentmodule: zlogging.enum.SOCKS
    RequestType['UDP_ASSOCIATE'] = enum.auto()
