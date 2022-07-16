# -*- coding: utf-8 -*-
"""Bro/Zeek log data model."""

import abc
import collections
import types
from typing import TYPE_CHECKING

from zlogging._aux import expand_typing
from zlogging._exc import ModelFormatError, ModelTypeError, ModelValueError

__all__ = [
    'Model', 'new_model',
]

if TYPE_CHECKING:
    from collections import OrderedDict
    from typing import Any, Optional, Type, Union

    from zlogging.types import _GenericType, _SimpleType, _VariadicType


class Model(metaclass=abc.ABCMeta):
    """Log data model.

    Args:
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    Warns:
        BroDeprecationWarning: Use of ``bro_*`` type annotations.

    Raises:
        :exc:`ModelValueError`: In case of inconsistency between field
            data types, or values of ``unset_field``, ``empty_field`` and
            ``set_separator``.
        :exc:`ModelTypeError`: Wrong parameters when initialisation.

    Note:
        Customise the :meth:`Model.__post_init__ <zlogging.model.Model.__post_init__>` method
        in your subclassed data model to implement your own ideas.

    Example:
        Define a custom log data model using the prefines Bro/Zeek data types,
        or subclasses of :class:`~zlogging.types.BaseType`:

        .. code-block:: python

            class MyLog(Model):
                field_one = StringType()
                field_two = SetType(element_type=PortType)

        Or you may use type annotations as :pep:`484` introduced when declaring
        data models. All available type hints can be found in
        :mod:`zlogging.typing`:

        .. code-block:: python

            class MyLog(Model):
                field_one: zeek_string
                field_two: zeek_set[zeek_port]

        However, when mixing annotations and direct assignments, annotations
        will take proceedings, i.e. the :class:`Model` class shall process first
        annotations then assignments. Should there be any conflicts,
        ``ModelError`` will be raised.

    See Also:

        See :func:`~zlogging._aux.expand_typing` for more information about
        processing the fields.

    """
    #: Fields of the data model.
    __fields__: 'OrderedDict[str, Union[_SimpleType, _GenericType]]'
    #: Fields of ``record`` data type in the data model.
    __record_fields__: 'OrderedDict[str, _VariadicType]'
    #: Placeholder for empty field.
    __empty_field__: 'bytes'
    #: Placeholder for unset field.
    __unset_field__: 'bytes'
    #: Separator for set/vector fields.
    __set_separator__: 'bytes'

    @property
    def fields(self) -> 'OrderedDict[str, Union[_SimpleType, _GenericType]]':
        """Fields of the data model."""
        return self.__fields__

    @property
    def unset_field(self) -> 'bytes':
        """Placeholder for empty field."""
        return self.__unset_field__

    @property
    def empty_field(self) -> 'bytes':
        """Placeholder for unset field."""
        return self.__empty_field__

    @property
    def set_separator(self) -> 'bytes':
        """Separator for set/vector fields."""
        return self.__set_separator__

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Model':  # pylint: disable=unused-argument
        expanded = expand_typing(cls, ModelValueError)

        cls.__fields__ = expanded['fields']
        cls.__record_fields__ = expanded['record_fields']
        cls.__doc__ = 'Initialise ``%s`` data model.' % cls.__name__  # pylint: disable=consider-using-f-string

        cls.__unset_field__ = expanded['unset_field']
        cls.__empty_field__ = expanded['empty_field']
        cls.__set_separator__ = expanded['set_separator']

        return super().__new__(cls)

    def __init__(self, *args: 'Any', **kwargs: 'Any') -> 'None':
        init_args = collections.OrderedDict()

        field_names = list(self.__fields__)
        if len(args) > len(field_names):
            raise ModelTypeError('__init__() takes %d positional arguments but %d were given' % (len(field_names), len(args)))  # pylint: disable=line-too-long,consider-using-f-string
        for index, arg in enumerate(args):
            name = field_names[index]
            init_args[name] = self.__fields__[name](arg)
        for arg, val in kwargs.items():
            if arg in init_args:
                raise ModelTypeError('__init__() got multiple values for argument %r' % arg)  # pylint: disable=consider-using-f-string
            if arg not in field_names:
                if arg in self.__record_fields__ and isinstance(val, dict):
                    for arg_nam, arg_val in val.items():
                        name = '%s.%s' % (arg, arg_nam)  # pylint: disable=consider-using-f-string
                        if name not in self.__fields__:
                            raise ModelTypeError('__init__() got an unexpected keyword argument %r' % name)  # pylint: disable=consider-using-f-string
                        init_args[name] = self.__fields__[name](arg_val)
                    continue
                raise ModelTypeError('__init__() got an unexpected keyword argument %r' % arg)  # pylint: disable=consider-using-f-string
            init_args[arg] = self.__fields__[arg](val)

        diff = []  # type: list[str]
        for field in field_names:
            if field in init_args:
                continue
            diff.append(field)
        if diff:
            length = len(diff)
            if length == 1:
                diff_args = repr(diff[0])
            elif length == 2:
                diff_args = '%r and %r' % tuple(diff)  # pylint: disable=consider-using-f-string
            else:
                diff_args = '%s, and %r' % (', '.join(map(repr, diff[:-1])), diff[-1])  # pylint: disable=consider-using-f-string
            raise ModelTypeError('missing %d required positional arguments: %s' % (length, diff_args))  # pylint: disable=consider-using-f-string

        for key, val in init_args.items():
            setattr(self, key, val)
        self.__post_init__()

    def __post_init__(self) -> 'None':
        """Post-processing customisation."""

    def __str__(self) -> 'str':
        fields = []  # type: list[str]
        for field in self.__fields__:
            value = getattr(self, field)
            fields.append('%s=%s' % (field, value))  # pylint: disable=consider-using-f-string
        return '%s(%s)' % (type(self).__name__, ', '.join(fields))  # pylint: disable=consider-using-f-string

    def __repr__(self) -> 'str':
        fields = []  # type: list[str]
        for field in self.__fields__:
            value = getattr(self, field)
            fields.append('%s=%s' % (field, value))  # pylint: disable=consider-using-f-string
        return '%s(%s)' % (type(self).__name__, ', '.join(fields))  # pylint: disable=consider-using-f-string

    def __call__(self, format: 'str') -> 'Any':  # pylint: disable=redefined-builtin
        """Serialise data model with given format.

        Args:
            format: Serialisation format.

        Returns:
            The serialised data.

        Raises:
            :exc:`ModelFormatError`: If ``format`` is not
                supproted, i.e. :meth:`Mode.to{format}` does not
                exist.

        """
        func = 'to%s' % format  # pylint: disable=consider-using-f-string
        if hasattr(self, func):
            return getattr(self, func)()
        raise ModelFormatError('unsupported format: %s' % format)  # pylint: disable=consider-using-f-string

    def tojson(self) -> 'OrderedDict[str, Any]':
        """Serialise data model as JSON log format.

        Returns:
            An :obj:`OrderedDict` mapping each field and serialised JSON
            serialisable data.

        """
        fields = collections.OrderedDict()
        for field, type_cls in self.__fields__.items():
            value = getattr(self, field)
            fields[field] = type_cls.tojson(value)
        return fields

    def toascii(self) -> 'OrderedDict[str, str]':
        """Serialise data model as ASCII log format.

        Returns:
            An :obj:`OrderedDict` mapping each field and serialised text data.

        """
        fields = collections.OrderedDict()
        for field, type_cls in self.__fields__.items():
            value = getattr(self, field)
            fields[field] = type_cls.toascii(value)
        return fields

    def asdict(self, dict_factory: 'Optional[Type[dict]]' = None) -> 'dict[str, Any]':
        """Convert data model as a dictionary mapping field names to field values.

        Args:
            dict_factory: If given, ``dict_factory`` will be used instead of
                built-in :obj:`dict`.

        Returns:
            A dictionary mapping field names to field values.

        """
        if dict_factory is None:
            dict_factory = dict
        fields = dict_factory()

        for field in self.__fields__:
            value = getattr(self, field)
            fields[field] = value
        return fields

    def astuple(self, tuple_factory: 'Optional[Type[tuple]]' = None) -> 'tuple[Any, ...]':
        """Convert data model as a tuple of field values.

        Args:
            tuple_factory: If given, ``tuple_factory`` will be used instead of
                built-in :class:`~collections.namedtuple`.

        Returns:
            A tuple of field values.

        """
        field_names = []  # type: list[str]
        field_value = []  # type: list[Any]
        for field in self.__fields__:
            value = getattr(self, field)
            field_names.append(field)
            field_value.append(value)

        if tuple_factory is None:
            model_name = type(self).__name__
            named_tuple = collections.namedtuple(model_name, field_names)  # type: ignore[misc]
            return named_tuple(*field_value)
        return tuple_factory(field_value)


def new_model(name: 'str', **fields: 'Any') -> 'Type[Model]':
    """Create a data model dynamically with the appropriate fields.

    Args:
        name: data model name
        **fields: defined fields of the data model

    Returns:
        Created data model.

    Examples:
        Typically, we define a data model by subclassing the :obj:`Model`
        class, as following:

        .. code-block:: python

            class MyLog(Model):
                field_one = StringType()
                field_two = SetType(element_type=PortType)

        when defining dynamically with :func:`new_model`, the definition above
        can be rewrote to:

        .. code-block:: python

            MyLog = new_model('MyLog', field_one=StringType(), field_two=SetType(element_type=PortType))

    """
    def gen_body(ns: 'dict[str, Any]') -> 'None':
        """Generate ``exec_body``."""
        for name, type_cls in fields.items():
            ns[name] = type_cls
    return types.new_class(name, (Model,), exec_body=gen_body)
