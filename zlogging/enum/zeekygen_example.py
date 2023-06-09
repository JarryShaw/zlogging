# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``ZeekygenExample``."""

from zlogging._compat import enum


@enum.unique
class SimpleEnum(enum.IntFlag):
    """Enum: ``ZeekygenExample::SimpleEnum``.

    Documentation for the “SimpleEnum” type goes here. It can span multiple lines.

    See Also:
        `zeekygen/example.zeek <https://docs.zeek.org/en/stable/scripts/zeekygen/example.zeek.html#type-ZeekygenExample::SimpleEnum>`__

    """

    _ignore_ = 'SimpleEnum _'
    SimpleEnum = vars()

    #: Documentation for particular enum values is added like this.
    #: And can also span multiple lines.
    ONE = enum.auto()

    #: Or this style is valid to document the preceding enum value.
    TWO = enum.auto()

    THREE = enum.auto()

    #: And some documentation for “FOUR”.
    FOUR = enum.auto()

    #: Also “FIVE”.
    FIVE = enum.auto()
