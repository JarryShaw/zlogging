# -*- coding: utf-8 -*-
"""Namespace: SMB.

:module: zlogging.enum.SMB
"""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """Abstracted actions for SMB file actions.

    c.f. `base/protocols/smb/main.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_READ'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_WRITE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_OPEN'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_CLOSE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_DELETE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_RENAME'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['FILE_SET_ATTRIBUTE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PIPE_READ'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PIPE_WRITE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PIPE_OPEN'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PIPE_CLOSE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PRINT_READ'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PRINT_WRITE'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PRINT_OPEN'] = enum.auto()

    #: :currentmodule: zlogging.enum.SMB
    Action['PRINT_CLOSE'] = enum.auto()
