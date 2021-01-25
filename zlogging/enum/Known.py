# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
"""Namespace: ``Known``."""

from zlogging._compat import enum


@enum.unique
class ModbusDeviceType(enum.IntFlag):
    """Enum: ``Known::ModbusDeviceType``.

    See Also:
        `policy/protocols/modbus/known-masters-slaves.zeek`_

    .. _policy/protocols/modbus/known-masters-slaves.zeek: https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/known-masters-slaves.zeek.html#type-Known::ModbusDeviceType

    """

    _ignore_ = 'ModbusDeviceType _'
    ModbusDeviceType = vars()

    ModbusDeviceType['MODBUS_MASTER'] = enum.auto()

    ModbusDeviceType['MODBUS_SLAVE'] = enum.auto()
