# -*- coding: utf-8 -*-
"""Namespace: SOCKS."""

import enum


@enum.unique
class RequestType(enum.IntFlag):
    """
    c.f. {html_path}
    """

    _ignore_ = 'RequestType _'
    RequestType = vars()

    RequestType['CONNECTION'] = enum.auto()

    RequestType['PORT'] = enum.auto()

    RequestType['UDP_ASSOCIATE'] = enum.auto()
