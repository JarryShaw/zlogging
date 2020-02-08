# -*- coding: utf-8 -*-
"""Typing annotations."""
# pylint: disable=unused-import,unused-wildcard-import

import ctypes
import datetime
import decimal
import enum
import ipaddress
import os
import typing
from typing import *

import pandas
import typing_extensions
from typing_extensions import *

with open(__file__, 'rb') as file:
    BinaryFile = typing.NewType('BinaryFile', type(file))

Args = typing.NewType('Args', typing.List[str])
Kwargs = typing.NewType('Kwargs', typing.Dict[str, typing.Any])

PathLike = typing.NewType('PathLike', os.PathLike)

uint16 = typing.NewType('uint16', ctypes.c_uint16)
int64 = typing.NewType('int64', ctypes.c_int64)
uint64 = typing.NewType('uint64', ctypes.c_uint64)

Decimal = typing.NewType('Decimal', decimal.Decimal)

DateTime = typing.NewType('DateTime', datetime.datetime)
TimeDelta = typing.NewType('TimeDelta', datetime.timedelta)

IPAddress = typing.NewType('IPAddress', typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address])
IPNetwork = typing.NewType('IPNetwork', typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network])

Enum = typing.NewType('Enum', enum.Enum)

DataFrame = typing.NewType('DataFrame', pandas.DataFrame)
