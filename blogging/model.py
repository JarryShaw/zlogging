# -*- coding: utf-8 -*-
"""Bro/Zeek log data model."""

import abc
import collections

import blogging._typing as typing
from blogging._exc import ModelError
from blogging.types import Type

__all__ = [
    'Model',
]


class Model(metaclass=abc.ABCMeta):
    """Log data model."""

    def __new__(cls, *args: typing.Args, **kwargs: typing.Kwargs):  # pylint: disable=unused-argument
        fields = collections.OrderedDict()
        for name, attr in cls.__dict__.items():
            if not isinstance(attr, Type):
                continue
            fields[name] = attr

        cls.__fields__ = fields
        cls.__doc__ = 'Initialise ``%s`` data model.' % cls.__name__

        return super().__new__(cls)

    def __init__(self, *args: typing.Args, **kwargs: typing.Kwargs):
        """Initialise data model."""
        init_args = collections.OrderedDict()

        field_names = list(self.__fields__)
        if len(args) > len(field_names):
            raise ModelError('__init__() takes %d positional arguments but %d were given' % (len(field_names), len(args)))  # pylint: disable=line-too-long
        for index, arg in enumerate(args):
            name = field_names[index]
            init_args[name] = self.__fields__[name](arg)
        for arg, val in kwargs.items():
            if arg in init_args:
                raise ModelError('__init__() got multiple values for argument %r' % arg)
            if arg not in field_names:
                raise ModelError('__init__() got an unexpected keyword argument %r' % arg)
            init_args[arg] = self.__fields__[arg](val)

        for key, val in init_args.items():
            setattr(self, key, val)
        self.__post_init__()

    def __post_init__(self):
        """Post-processing customisation."""
