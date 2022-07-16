# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``NFS3``."""

from zlogging._compat import enum


@enum.unique
class createmode_t(enum.IntFlag):
    """Enum: ``NFS3::createmode_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-NFS3::createmode_t>`__

    """

    _ignore_ = 'createmode_t _'
    createmode_t = vars()

    UNCHECKED = enum.auto()

    GUARDED = enum.auto()

    EXCLUSIVE = enum.auto()


@enum.unique
class file_type_t(enum.IntFlag):
    """Enum: ``NFS3::file_type_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-NFS3::file_type_t>`__

    """

    _ignore_ = 'file_type_t _'
    file_type_t = vars()

    FTYPE_REG = enum.auto()

    FTYPE_DIR = enum.auto()

    FTYPE_BLK = enum.auto()

    FTYPE_CHR = enum.auto()

    FTYPE_LNK = enum.auto()

    FTYPE_SOCK = enum.auto()

    FTYPE_FIFO = enum.auto()


@enum.unique
class proc_t(enum.IntFlag):
    """Enum: ``NFS3::proc_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-NFS3::proc_t>`__

    """

    _ignore_ = 'proc_t _'
    proc_t = vars()

    PROC_NULL = enum.auto()

    PROC_GETATTR = enum.auto()

    PROC_SETATTR = enum.auto()

    PROC_LOOKUP = enum.auto()

    PROC_ACCESS = enum.auto()

    PROC_READLINK = enum.auto()

    PROC_READ = enum.auto()

    PROC_WRITE = enum.auto()

    PROC_CREATE = enum.auto()

    PROC_MKDIR = enum.auto()

    PROC_SYMLINK = enum.auto()

    PROC_MKNOD = enum.auto()

    PROC_REMOVE = enum.auto()

    PROC_RMDIR = enum.auto()

    PROC_RENAME = enum.auto()

    PROC_LINK = enum.auto()

    PROC_READDIR = enum.auto()

    PROC_READDIRPLUS = enum.auto()

    PROC_FSSTAT = enum.auto()

    PROC_FSINFO = enum.auto()

    PROC_PATHCONF = enum.auto()

    PROC_COMMIT = enum.auto()

    PROC_END_OF_PROCS = enum.auto()


@enum.unique
class stable_how_t(enum.IntFlag):
    """Enum: ``NFS3::stable_how_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-NFS3::stable_how_t>`__

    """

    _ignore_ = 'stable_how_t _'
    stable_how_t = vars()

    UNSTABLE = enum.auto()

    DATA_SYNC = enum.auto()

    FILE_SYNC = enum.auto()


@enum.unique
class status_t(enum.IntFlag):
    """Enum: ``NFS3::status_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-NFS3::status_t>`__

    """

    _ignore_ = 'status_t _'
    status_t = vars()

    NFS3ERR_OK = enum.auto()

    NFS3ERR_PERM = enum.auto()

    NFS3ERR_NOENT = enum.auto()

    NFS3ERR_IO = enum.auto()

    NFS3ERR_NXIO = enum.auto()

    NFS3ERR_ACCES = enum.auto()

    NFS3ERR_EXIST = enum.auto()

    NFS3ERR_XDEV = enum.auto()

    NFS3ERR_NODEV = enum.auto()

    NFS3ERR_NOTDIR = enum.auto()

    NFS3ERR_ISDIR = enum.auto()

    NFS3ERR_INVAL = enum.auto()

    NFS3ERR_FBIG = enum.auto()

    NFS3ERR_NOSPC = enum.auto()

    NFS3ERR_ROFS = enum.auto()

    NFS3ERR_MLINK = enum.auto()

    NFS3ERR_NAMETOOLONG = enum.auto()

    NFS3ERR_NOTEMPTY = enum.auto()

    NFS3ERR_DQUOT = enum.auto()

    NFS3ERR_STALE = enum.auto()

    NFS3ERR_REMOTE = enum.auto()

    NFS3ERR_BADHANDLE = enum.auto()

    NFS3ERR_NOT_SYNC = enum.auto()

    NFS3ERR_BAD_COOKIE = enum.auto()

    NFS3ERR_NOTSUPP = enum.auto()

    NFS3ERR_TOOSMALL = enum.auto()

    NFS3ERR_SERVERFAULT = enum.auto()

    NFS3ERR_BADTYPE = enum.auto()

    NFS3ERR_JUKEBOX = enum.auto()

    NFS3ERR_UNKNOWN = enum.auto()


@enum.unique
class time_how_t(enum.IntFlag):
    """Enum: ``NFS3::time_how_t``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-NFS3::time_how_t>`__

    """

    _ignore_ = 'time_how_t _'
    time_how_t = vars()

    DONT_CHANGE = enum.auto()

    SET_TO_SERVER_TIME = enum.auto()

    SET_TO_CLIENT_TIME = enum.auto()
