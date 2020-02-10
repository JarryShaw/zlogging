# -*- coding: utf-8 -*-
"""Namespace: Weird.

:module: zlogging.enum.Weird
"""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """Types of actions that may be taken when handling weird activity events.

    c.f. `base/frameworks/notice/weird.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/weird.zeek.html>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: A dummy action indicating the user does not care what
    #: internal decision is made regarding a given type of weird.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_UNSPECIFIED'] = enum.auto()

    #: No action is to be taken.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_IGNORE'] = enum.auto()

    #: Log the weird event every time it occurs.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_LOG'] = enum.auto()

    #: Log the weird event only once.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_LOG_ONCE'] = enum.auto()

    #: Log the weird event once per connection.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_LOG_PER_CONN'] = enum.auto()

    #: Log the weird event once per originator host.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_LOG_PER_ORIG'] = enum.auto()

    #: Always generate a notice associated with the weird event.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_NOTICE'] = enum.auto()

    #: Generate a notice associated with the weird event only once.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_NOTICE_ONCE'] = enum.auto()

    #: Generate a notice for the weird event once per connection.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_NOTICE_PER_CONN'] = enum.auto()

    #: Generate a notice for the weird event once per originator host.
    #: :currentmodule: zlogging.enum.Weird
    Action['ACTION_NOTICE_PER_ORIG'] = enum.auto()
