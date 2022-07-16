# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``MOUNT3``."""

from zlogging._compat import enum


@enum.unique
class auth_flavor_t(enum.IntFlag):
    """Enum: ``MOUNT3::auth_flavor_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-MOUNT3::auth_flavor_t>`__

    """

    _ignore_ = 'auth_flavor_t _'
    auth_flavor_t = vars()

    AUTH_NULL = enum.auto()

    AUTH_UNIX = enum.auto()

    AUTH_SHORT = enum.auto()

    AUTH_DES = enum.auto()


@enum.unique
class proc_t(enum.IntFlag):
    """Enum: ``MOUNT3::proc_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-MOUNT3::proc_t>`__

    """

    _ignore_ = 'proc_t _'
    proc_t = vars()

    PROC_NULL = enum.auto()

    PROC_MNT = enum.auto()

    PROC_DUMP = enum.auto()

    PROC_UMNT = enum.auto()

    PROC_UMNT_ALL = enum.auto()

    PROC_EXPORT = enum.auto()

    PROC_END_OF_PROCS = enum.auto()


@enum.unique
class status_t(enum.IntFlag):
    """Enum: ``MOUNT3::status_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-MOUNT3::status_t>`__

    """

    _ignore_ = 'status_t _'
    status_t = vars()

    MNT3_OK = enum.auto()

    MNT3ERR_PERM = enum.auto()

    MNT3ERR_NOENT = enum.auto()

    MNT3ERR_IO = enum.auto()

    MNT3ERR_ACCES = enum.auto()

    MNT3ERR_NOTDIR = enum.auto()

    MNT3ERR_INVAL = enum.auto()

    MNT3ERR_NAMETOOLONG = enum.auto()

    MNT3ERR_NOTSUPP = enum.auto()

    MNT3ERR_SERVERFAULT = enum.auto()

    MOUNT3ERR_UNKNOWN = enum.auto()
