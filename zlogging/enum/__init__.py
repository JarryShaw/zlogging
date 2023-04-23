# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports,duplicate-key
"""Bro/Zeek enum namespace."""

import builtins
import warnings
from typing import TYPE_CHECKING

from zlogging._exc import BroDeprecationWarning

__all__ = ['globals']

if TYPE_CHECKING:
    from enum import Enum


def globals(*namespaces: 'str', bare: 'bool' = False) -> 'dict[str, Enum]':  # pylint: disable=redefined-builtin
    """Generate Bro/Zeek ``enum`` namespace.

    Args:
        *namespaces: Namespaces to be loaded.
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Returns:
        Global enum namespace.

    Warns:
        BroDeprecationWarning: If ``bro`` namespace used.

    Raises:
        :exc:`ValueError`: If ``namespace`` is not defined.

    Note:
        For back-port compatibility, the ``bro`` namespace is an alias of the
        ``zeek`` namespace.

    """
    if bare:
        enum_data = {}  # type: dict[str, Enum]
    else:
        enum_data = _enum_zeek.copy()
    for namespace in namespaces:
        if namespace == 'bro':
            warnings.warn("Use of 'bro' is deprecated. "
                          "Please use 'zeek' instead.", BroDeprecationWarning)
            namespace = 'zeek'

        enum_dict = builtins.globals().get('_enum_%s' % namespace)  # pylint: disable=consider-using-f-string
        if enum_dict is None:
            raise ValueError('undefined namespace: %s' % namespace)  # pylint: disable=consider-using-f-string
        enum_data.update(enum_dict)
    return enum_data
