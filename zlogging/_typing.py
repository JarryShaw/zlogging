# -*- coding: utf-8 -*-
# pylint: disable=unsubscriptable-object
"""Typing annotations."""

from collections import OrderedDict
from typing import Union

from typing_extensions import TypedDict

from zlogging.types import _GenericType, _SimpleType, _VariadicType


class ExpandedTyping(TypedDict):
    """Return type of :func:`zlogging._aux.expand_typing`."""

    fields: OrderedDict[str, Union[_SimpleType, _GenericType]]
    record_fields: OrderedDict[str, _VariadicType]
    unset_field: bytes
    empty_field: bytes
    set_separator: bytes
