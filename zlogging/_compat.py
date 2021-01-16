# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Resolve compatibility issues."""

import sys
from typing import TYPE_CHECKING

from typing_extensions import DefaultDict

__all__ = [
    'enum',
    'GenericMeta',
    'cached_property',
]

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type, Union

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

# functools.cached_property added in 3.8
if version_info >= (3, 8):
    from functools import cached_property
else:
    from _thread import RLock  # type: ignore[attr-defined]
    from typing import Generic, TypeVar, overload  # isort: split

    _T = TypeVar("_T")
    _S = TypeVar("_S")

    _NOT_FOUND = object()

    class cached_property(Generic[_T]):  # type: ignore[no-redef]
        def __init__(self, func: 'Callable[[Any], _T]') -> None:
            self.func = func  # type: Callable[[Any], _T]
            self.attrname = None  # type: Optional[str]
            self.__doc__ = func.__doc__
            self.lock = RLock()

        def __set_name__(self, owner: 'Type[Any]', name: str) -> None:
            if self.attrname is None:
                self.attrname = name
            elif name != self.attrname:
                raise TypeError(
                    "Cannot assign the same cached_property to two different names "
                    f"({self.attrname!r} and {name!r})."
                )

        @overload
        def __get__(self, instance: None, owner: 'Optional[Type[Any]]' = ...) -> 'cached_property[_T]': ...
        @overload
        def __get__(self, instance: _S, owner: 'Optional[Type[Any]]' = ...) -> '_T': ...

        def __get__(self, instance: 'Optional[_S]',
                    owner: 'Optional[Type[Any]]' = None) -> 'Union[cached_property[_T], _T]':
            if instance is None:
                return self  # type: ignore[return-value]
            if self.attrname is None:
                raise TypeError(
                    "Cannot use cached_property instance without calling __set_name__ on it.")
            try:
                cache = instance.__dict__
            except AttributeError:  # not all objects have __dict__ (e.g. class defines slots)
                msg = (
                    f"No '__dict__' attribute on {type(instance).__name__!r} "
                    f"instance to cache {self.attrname!r} property."
                )
                raise TypeError(msg) from None
            val = cache.get(self.attrname, _NOT_FOUND)
            if val is _NOT_FOUND:
                with self.lock:
                    # check if another thread filled cache while we awaited lock
                    val = cache.get(self.attrname, _NOT_FOUND)
                    if val is _NOT_FOUND:
                        val = self.func(instance)
                        try:
                            cache[self.attrname] = val
                        except TypeError:
                            msg = (
                                f"The '__dict__' attribute on {type(instance).__name__!r} instance "
                                f"does not support item assignment for caching {self.attrname!r} property."
                            )
                            raise TypeError(msg) from None
            return val
