# -*- coding: utf-8 -*-
"""Typing annotations."""
# pylint: disable=unused-import,unused-wildcard-import

import ctypes
import datetime
import decimal
import ipaddress
import os
import typing
from typing import *

from zlogging._compat import *

T = typing.TypeVar('T')

with open(__file__, 'rb') as file:
    BinaryFile = type(file)

with open(__file__, 'r') as file:
    TextFile = type(file)

Args = typing.List[str]
Kwargs = typing.Dict[str, typing.Any]

PathLike = os.PathLike

uint16 = ctypes.c_uint16
int64 = ctypes.c_int64
uint64 = ctypes.c_uint64

Decimal = decimal.Decimal

DateTime = datetime.datetime
TimeDelta = datetime.timedelta

IPAddress = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

Enum = enum.Enum
