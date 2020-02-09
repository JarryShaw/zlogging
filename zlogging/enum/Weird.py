# -*- coding: utf-8 -*-
"""Namespace: Weird."""

import enum


@enum.unique
class Action(enum.IntFlag):
    """Types of actions that may be taken when handling weird activity events.

    
    c.f. {html_path}
    """

    _ignore_ = 'Action _'
    Action = vars()

    # A dummy action indicating the user does not care what
    # internal decision is made regarding a given type of weird.
    Action['ACTION_UNSPECIFIED'] = enum.auto()

    # No action is to be taken.
    Action['ACTION_IGNORE'] = enum.auto()

    # Log the weird event every time it occurs.
    Action['ACTION_LOG'] = enum.auto()

    # Log the weird event only once.
    Action['ACTION_LOG_ONCE'] = enum.auto()

    # Log the weird event once per connection.
    Action['ACTION_LOG_PER_CONN'] = enum.auto()

    # Log the weird event once per originator host.
    Action['ACTION_LOG_PER_ORIG'] = enum.auto()

    # Always generate a notice associated with the weird event.
    Action['ACTION_NOTICE'] = enum.auto()

    # Generate a notice associated with the weird event only once.
    Action['ACTION_NOTICE_ONCE'] = enum.auto()

    # Generate a notice for the weird event once per connection.
    Action['ACTION_NOTICE_PER_CONN'] = enum.auto()

    # Generate a notice for the weird event once per originator host.
    Action['ACTION_NOTICE_PER_ORIG'] = enum.auto()
