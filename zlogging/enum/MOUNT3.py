# -*- coding: utf-8 -*-
"""Namespace: MOUNT3.

:module: zlogging.enum.MOUNT3
"""

from zlogging._compat import enum


@enum.unique
class auth_flavor_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'auth_flavor_t _'
    auth_flavor_t = vars()

    #: :currentmodule: zlogging.enum.MOUNT3
    auth_flavor_t['AUTH_NULL'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    auth_flavor_t['AUTH_UNIX'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    auth_flavor_t['AUTH_SHORT'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    auth_flavor_t['AUTH_DES'] = enum.auto()


@enum.unique
class proc_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'proc_t _'
    proc_t = vars()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_NULL'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_MNT'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_DUMP'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_UMNT'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_UMNT_ALL'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_EXPORT'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    proc_t['PROC_END_OF_PROCS'] = enum.auto()


@enum.unique
class status_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'status_t _'
    status_t = vars()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3_OK'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_PERM'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_NOENT'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_IO'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_ACCES'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_NOTDIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_INVAL'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_NAMETOOLONG'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_NOTSUPP'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MNT3ERR_SERVERFAULT'] = enum.auto()

    #: :currentmodule: zlogging.enum.MOUNT3
    status_t['MOUNT3ERR_UNKNOWN'] = enum.auto()
