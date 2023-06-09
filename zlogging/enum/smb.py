# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``SMB``."""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """Enum: ``SMB::Action``.

    Abstracted actions for SMB file actions.

    See Also:
        `base/protocols/smb/main.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::Action>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    FILE_READ = enum.auto()

    FILE_WRITE = enum.auto()

    FILE_OPEN = enum.auto()

    FILE_CLOSE = enum.auto()

    FILE_DELETE = enum.auto()

    FILE_RENAME = enum.auto()

    FILE_SET_ATTRIBUTE = enum.auto()

    PIPE_READ = enum.auto()

    PIPE_WRITE = enum.auto()

    PIPE_OPEN = enum.auto()

    PIPE_CLOSE = enum.auto()

    PRINT_READ = enum.auto()

    PRINT_WRITE = enum.auto()

    PRINT_OPEN = enum.auto()

    PRINT_CLOSE = enum.auto()
