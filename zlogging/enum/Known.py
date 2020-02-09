# -*- coding: utf-8 -*-
"""Namespace: Known."""

import enum


@enum.unique
class ModbusDeviceType(enum.IntFlag):
    """
    c.f. {html_path}
    """

    _ignore_ = 'ModbusDeviceType _'
    ModbusDeviceType = vars()

    ModbusDeviceType['MODBUS_MASTER'] = enum.auto()

    ModbusDeviceType['MODBUS_SLAVE'] = enum.auto()
