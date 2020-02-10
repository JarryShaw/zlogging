# -*- coding: utf-8 -*-
"""Namespace: Known.

:module: zlogging.enum.Known
"""

from zlogging._compat import enum


@enum.unique
class ModbusDeviceType(enum.IntFlag):
    """c.f. `policy/protocols/modbus/known-masters-slaves.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/known-masters-slaves.zeek.html>`__"""

    _ignore_ = 'ModbusDeviceType _'
    ModbusDeviceType = vars()

    #: :currentmodule: zlogging.enum.Known
    ModbusDeviceType['MODBUS_MASTER'] = enum.auto()

    #: :currentmodule: zlogging.enum.Known
    ModbusDeviceType['MODBUS_SLAVE'] = enum.auto()
