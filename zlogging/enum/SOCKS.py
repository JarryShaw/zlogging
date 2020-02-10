# -*- coding: utf-8 -*-
"""Namespace: SOCKS."""

import enum


@enum.unique
class RequestType(enum.IntFlag):
    """
    c.f. `base/protocols/socks/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/socks/consts.zeek.html>`__
    """

    _ignore_ = 'RequestType _'
    RequestType = vars()

    RequestType['CONNECTION'] = enum.auto()

    RequestType['PORT'] = enum.auto()

    RequestType['UDP_ASSOCIATE'] = enum.auto()
