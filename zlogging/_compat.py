# -*- coding: utf-8 -*-
"""Resolve compatibility issues."""

__all__ = [
    'enum',
    'NoReturn',
    'OrderedDict',
    'GenericMeta',
]

# enum.Enum._ignore_ added in 3.7
try:
    import aenum as enum
except ImportError:
    import enum

# typing.NoReturn added in 3.5.4/3.6.2
try:
    from typing import NoReturn  # pylint: disable=ungrouped-imports
except ImportError:
    from typing import _FinalTypingBase

    class _NoReturn(_FinalTypingBase, _root=True):
        """Special type indicating functions that never return.
        Example::

        from typing import NoReturn

        def stop() -> NoReturn:
            raise Exception('no way')

        This type is invalid in other positions, e.g., ``List[NoReturn]``
        will fail in static type checkers.
        """

        __slots__ = ()

        def __instancecheck__(self, obj):
            raise TypeError("NoReturn cannot be used with isinstance().")

        def __subclasscheck__(self, cls):
            raise TypeError("NoReturn cannot be used with issubclass().")

    NoReturn = _NoReturn(_root=True)

# typing.OrderedDict added in 3.7.3
try:
    from typing import OrderedDict  # pylint: disable=ungrouped-imports
except ImportError:
    import collections
    import typing

    KT = typing.TypeVar('KT')
    VT = typing.TypeVar('VT')

    class OrderedDict(collections.OrderedDict, typing.Generic[KT, VT]):
        pass

# 3.6  GenericMeta
# 3.7+ _GenericAlias
GenericMeta = type(OrderedDict)
