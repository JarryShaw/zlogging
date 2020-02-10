# -*- coding: utf-8 -*-
"""Namespace: ``DCE_RPC``."""

from zlogging._compat import enum


@enum.unique
class IfID(enum.IntFlag):
    """c.f. `base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek.html#type-DCE_RPC::IfID>`__"""

    _ignore_ = 'IfID _'
    IfID = vars()

    IfID['unknown_if'] = enum.auto()

    IfID['epmapper'] = enum.auto()

    IfID['lsarpc'] = enum.auto()

    IfID['lsa_ds'] = enum.auto()

    IfID['mgmt'] = enum.auto()

    IfID['netlogon'] = enum.auto()

    IfID['samr'] = enum.auto()

    IfID['srvsvc'] = enum.auto()

    IfID['spoolss'] = enum.auto()

    IfID['drs'] = enum.auto()

    IfID['winspipe'] = enum.auto()

    IfID['wkssvc'] = enum.auto()

    IfID['oxid'] = enum.auto()

    IfID['ISCMActivator'] = enum.auto()


@enum.unique
class PType(enum.IntFlag):
    """c.f. `base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek.html#type-DCE_RPC::PType>`__"""

    _ignore_ = 'PType _'
    PType = vars()

    PType['REQUEST'] = enum.auto()

    PType['PING'] = enum.auto()

    PType['RESPONSE'] = enum.auto()

    PType['FAULT'] = enum.auto()

    PType['WORKING'] = enum.auto()

    PType['NOCALL'] = enum.auto()

    PType['REJECT'] = enum.auto()

    PType['ACK'] = enum.auto()

    PType['CL_CANCEL'] = enum.auto()

    PType['FACK'] = enum.auto()

    PType['CANCEL_ACK'] = enum.auto()

    PType['BIND'] = enum.auto()

    PType['BIND_ACK'] = enum.auto()

    PType['BIND_NAK'] = enum.auto()

    PType['ALTER_CONTEXT'] = enum.auto()

    PType['ALTER_CONTEXT_RESP'] = enum.auto()

    PType['AUTH3'] = enum.auto()

    PType['SHUTDOWN'] = enum.auto()

    PType['CO_CANCEL'] = enum.auto()

    PType['ORPHANED'] = enum.auto()

    PType['RTS'] = enum.auto()
