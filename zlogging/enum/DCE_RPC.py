# -*- coding: utf-8 -*-
"""Namespace: DCE_RPC.

:module: zlogging.enum.DCE_RPC
"""

from zlogging._compat import enum


@enum.unique
class IfID(enum.IntFlag):
    """c.f. `base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek.html>`__"""

    _ignore_ = 'IfID _'
    IfID = vars()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['unknown_if'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['epmapper'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['lsarpc'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['lsa_ds'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['mgmt'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['netlogon'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['samr'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['srvsvc'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['spoolss'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['drs'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['winspipe'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['wkssvc'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['oxid'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    IfID['ISCMActivator'] = enum.auto()


@enum.unique
class PType(enum.IntFlag):
    """c.f. `base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek.html>`__"""

    _ignore_ = 'PType _'
    PType = vars()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['REQUEST'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['PING'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['RESPONSE'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['FAULT'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['WORKING'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['NOCALL'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['REJECT'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['ACK'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['CL_CANCEL'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['FACK'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['CANCEL_ACK'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['BIND'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['BIND_ACK'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['BIND_NAK'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['ALTER_CONTEXT'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['ALTER_CONTEXT_RESP'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['AUTH3'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['SHUTDOWN'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['CO_CANCEL'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['ORPHANED'] = enum.auto()

    #: :currentmodule: zlogging.enum.DCE_RPC
    PType['RTS'] = enum.auto()
