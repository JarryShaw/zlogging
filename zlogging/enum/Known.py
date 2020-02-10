# -*- coding: utf-8 -*-
"""Namespace: Known."""

import enum


@enum.unique
class ModbusDeviceType(enum.IntFlag):
    """
    c.f. `policy/protocols/modbus/known-masters-slaves.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/known-masters-slaves.zeek.html>`__
    """

    _ignore_ = 'ModbusDeviceType _'
    ModbusDeviceType = vars()

    ModbusDeviceType['MODBUS_MASTER'] = enum.auto()

    ModbusDeviceType['MODBUS_SLAVE'] = enum.auto()
