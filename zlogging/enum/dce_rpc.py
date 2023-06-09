# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``DCE_RPC``."""

from zlogging._compat import enum


@enum.unique
class IfID(enum.IntFlag):
    """Enum: ``DCE_RPC::IfID``.

    See Also:
        `base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek.html#type-DCE_RPC::IfID>`__

    """

    _ignore_ = 'IfID _'
    IfID = vars()

    unknown_if = enum.auto()

    epmapper = enum.auto()

    lsarpc = enum.auto()

    lsa_ds = enum.auto()

    mgmt = enum.auto()

    netlogon = enum.auto()

    samr = enum.auto()

    srvsvc = enum.auto()

    spoolss = enum.auto()

    drs = enum.auto()

    winspipe = enum.auto()

    wkssvc = enum.auto()

    oxid = enum.auto()

    ISCMActivator = enum.auto()


@enum.unique
class PType(enum.IntFlag):
    """Enum: ``DCE_RPC::PType``.

    See Also:
        `base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek.html#type-DCE_RPC::PType>`__

    """

    _ignore_ = 'PType _'
    PType = vars()

    REQUEST = enum.auto()

    PING = enum.auto()

    RESPONSE = enum.auto()

    FAULT = enum.auto()

    WORKING = enum.auto()

    NOCALL = enum.auto()

    REJECT = enum.auto()

    ACK = enum.auto()

    CL_CANCEL = enum.auto()

    FACK = enum.auto()

    CANCEL_ACK = enum.auto()

    BIND = enum.auto()

    BIND_ACK = enum.auto()

    BIND_NAK = enum.auto()

    ALTER_CONTEXT = enum.auto()

    ALTER_CONTEXT_RESP = enum.auto()

    AUTH3 = enum.auto()

    SHUTDOWN = enum.auto()

    CO_CANCEL = enum.auto()

    ORPHANED = enum.auto()

    RTS = enum.auto()
