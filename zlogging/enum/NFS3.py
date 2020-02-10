# -*- coding: utf-8 -*-
"""Namespace: NFS3.

:module: zlogging.enum.NFS3
"""

from zlogging._compat import enum


@enum.unique
class createmode_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'createmode_t _'
    createmode_t = vars()

    #: :currentmodule: zlogging.enum.NFS3
    createmode_t['UNCHECKED'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    createmode_t['GUARDED'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    createmode_t['EXCLUSIVE'] = enum.auto()


@enum.unique
class file_type_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'file_type_t _'
    file_type_t = vars()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_REG'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_DIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_BLK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_CHR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_LNK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_SOCK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    file_type_t['FTYPE_FIFO'] = enum.auto()


@enum.unique
class proc_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'proc_t _'
    proc_t = vars()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_NULL'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_GETATTR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_SETATTR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_LOOKUP'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_ACCESS'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_READLINK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_READ'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_WRITE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_CREATE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_MKDIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_SYMLINK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_MKNOD'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_REMOVE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_RMDIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_RENAME'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_LINK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_READDIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_READDIRPLUS'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_FSSTAT'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_FSINFO'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_PATHCONF'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_COMMIT'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    proc_t['PROC_END_OF_PROCS'] = enum.auto()


@enum.unique
class stable_how_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'stable_how_t _'
    stable_how_t = vars()

    #: :currentmodule: zlogging.enum.NFS3
    stable_how_t['UNSTABLE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    stable_how_t['DATA_SYNC'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    stable_how_t['FILE_SYNC'] = enum.auto()


@enum.unique
class status_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'status_t _'
    status_t = vars()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_OK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_PERM'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NOENT'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_IO'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NXIO'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_ACCES'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_EXIST'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_XDEV'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NODEV'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NOTDIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_ISDIR'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_INVAL'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_FBIG'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NOSPC'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_ROFS'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_MLINK'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NAMETOOLONG'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NOTEMPTY'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_DQUOT'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_STALE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_REMOTE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_BADHANDLE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NOT_SYNC'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_BAD_COOKIE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_NOTSUPP'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_TOOSMALL'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_SERVERFAULT'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_BADTYPE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_JUKEBOX'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    status_t['NFS3ERR_UNKNOWN'] = enum.auto()


@enum.unique
class time_how_t(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'time_how_t _'
    time_how_t = vars()

    #: :currentmodule: zlogging.enum.NFS3
    time_how_t['DONT_CHANGE'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    time_how_t['SET_TO_SERVER_TIME'] = enum.auto()

    #: :currentmodule: zlogging.enum.NFS3
    time_how_t['SET_TO_CLIENT_TIME'] = enum.auto()
