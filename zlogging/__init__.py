# -*- coding: utf-8 -*-
"""Bro/Zeek logging framework."""

###############################################################################
# conda ``_extern`` module support

import os
import sys

_extern = os.path.join(os.path.dirname(os.path.realpath(__file__)), '_extern')
if os.path.exists(_extern):
    sys.path.append(_extern)

###############################################################################

from zlogging.dumper import dump, dumps, write
from zlogging.loader import load, loads, parse
from zlogging.model import Model, new_model
from zlogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                            IntType, PortType, RecordType, SetType, StringType, SubnetType,
                            TimeType, VectorType)

__all__ = [
    'write', 'dump', 'dumps',
    'parse', 'load', 'loads',

    'Model', 'new_model',

    'AddrType', 'BoolType', 'CountType', 'DoubleType', 'EnumType',
    'IntervalType', 'IntType', 'PortType', 'RecordType', 'SetType',
    'StringType', 'SubnetType', 'TimeType', 'VectorType',
]

# version string
__version__ = '0.1.3.post3'
