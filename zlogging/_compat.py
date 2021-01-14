# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Resolve compatibility issues."""

import sys

from typing_extensions import DefaultDict

__all__ = [
    'enum',
    'GenericMeta',
]

version_info = sys.version_info[:2]

# enum.Enum._ignore_ added in 3.7
if version_info < (3, 7):
    import aenum as enum
else:
    import enum  # type: ignore[no-redef]

# 3.6  GenericMeta
# 3.7+ _GenericAlias
# 3.9+ _SpecialGenericAlias
GenericMeta = type(DefaultDict)
