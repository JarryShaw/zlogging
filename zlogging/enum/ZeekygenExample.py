# -*- coding: utf-8 -*-
"""Namespace: ZeekygenExample.

:module: zlogging.enum.ZeekygenExample
"""

from zlogging._compat import enum


@enum.unique
class SimpleEnum(enum.IntFlag):
    """Documentation for the “SimpleEnum” type goes here.
    It can span multiple lines.

    c.f. `zeekygen/example.zeek <https://docs.zeek.org/en/stable/scripts/zeekygen/example.zeek.html>`__

    """

    _ignore_ = 'SimpleEnum _'
    SimpleEnum = vars()

    #: Documentation for particular enum values is added like this.
    #: And can also span multiple lines.
    #: :currentmodule: zlogging.enum.ZeekygenExample
    SimpleEnum['ONE'] = enum.auto()

    #: Or this style is valid to document the preceding enum value.
    #: :currentmodule: zlogging.enum.ZeekygenExample
    SimpleEnum['TWO'] = enum.auto()

    #: :currentmodule: zlogging.enum.ZeekygenExample
    SimpleEnum['THREE'] = enum.auto()

    #: And some documentation for “FOUR”.
    #: :currentmodule: zlogging.enum.ZeekygenExample
    SimpleEnum['FOUR'] = enum.auto()

    #: Also “FIVE”.
    #: :currentmodule: zlogging.enum.ZeekygenExample
    SimpleEnum['FIVE'] = enum.auto()
