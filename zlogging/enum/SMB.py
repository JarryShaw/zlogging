# -*- coding: utf-8 -*-
"""Namespace: ``SMB``."""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """Abstracted actions for SMB file actions.

    c.f. `base/protocols/smb/main.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::Action>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    Action['FILE_READ'] = enum.auto()

    Action['FILE_WRITE'] = enum.auto()

    Action['FILE_OPEN'] = enum.auto()

    Action['FILE_CLOSE'] = enum.auto()

    Action['FILE_DELETE'] = enum.auto()

    Action['FILE_RENAME'] = enum.auto()

    Action['FILE_SET_ATTRIBUTE'] = enum.auto()

    Action['PIPE_READ'] = enum.auto()

    Action['PIPE_WRITE'] = enum.auto()

    Action['PIPE_OPEN'] = enum.auto()

    Action['PIPE_CLOSE'] = enum.auto()

    Action['PRINT_READ'] = enum.auto()

    Action['PRINT_WRITE'] = enum.auto()

    Action['PRINT_OPEN'] = enum.auto()

    Action['PRINT_CLOSE'] = enum.auto()
