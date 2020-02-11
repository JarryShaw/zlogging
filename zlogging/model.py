# -*- coding: utf-8 -*-
"""Bro/Zeek log data model."""

import abc
import collections
import types

import zlogging._typing as typing
from zlogging._aux import expand_typing
from zlogging._exc import ModelTypeError, ModelValueError, ModelFormatError
from zlogging.types import BaseType

__all__ = [
    'Model', 'new_model',
]


class Model(metaclass=abc.ABCMeta):
    """Log data model.

    Attributes:
        __fields__ (:obj:`OrderedDict` mapping :obj:`str` and :class:`~zlogging.types.BaseType`):
            Fields of the data model.
        __record_fields__ (:obj:`OrderedDict` mapping :obj:`str` and :class:`RecordType`):
            Fields of ``record`` data type in the data model.
        __empty_field__ (bytes): Placeholder for empty field.
        __unset_field__ (bytes): Placeholder for unset field.
        __set_separator__ (bytes): Separator for set/vector fields.

    Warns:
        BroDeprecationWarning: Use of ``bro_*`` type annotations.

    Raises:
        :exc:`ModelValueError`: In case of inconsistency between field
            data types, or values of ``unset_field``, ``empty_field`` and
            ``set_separator``.
        :exc:`ModelTypeError`: Wrong parameters when initialisation.

    Note:
        Customise the :meth:`Model.__post_init__ <zlogging.mode.Model.__post_init__>` method
        in your subclassed data model to implement your own ideas.

    Example:
        Define a custom log data model using the prefines Bro/Zeek data types,
        or subclasses of :class:`~zlogging.types.BaseType`::

            class MyLog(Model):
                field_one = StringType()
                field_two = SetType(element_type=PortType)

        Or you may use type annotations as `PEP 484`_ introduced when declaring
        data models. All available type hints can be found in
        :mod:`~zlogging.typing`::

            class MyLog(Model):
                field_one: zeek_string
                field_two: zeek_set[zeek_port]

        However, when mixing annotations and direct assignments, annotations
        will take proceedings, i.e. the :class:`Model` class shall process first
        annotations then assignments. Should there be any conflicts,
        ``ModelError`` will be raised.

    See Also:

        See :func:`~zlogging._aux_expand_typing` for more information about
        processing the fields.

    .. _PEP 484:
        https://www.python.org/dev/peps/pep-0484/

    """

    @property
    def fields(self) -> typing.OrderedDict[str, BaseType]:
        """:obj:`OrderedDict` mapping :obj:`str` and :class:`~zlogging.types.BaseType`: fields of the data model"""
        return self.__fields__

    @property
    def unset_field(self) -> bytes:
        """bytes: placeholder for empty field"""
        return self.__unset_field__

    @property
    def empty_field(self) -> bytes:
        """bytes: placeholder for unset field"""
        return self.__empty_field__

    @property
    def set_separator(self) -> bytes:
        """bytes: separator for set/vector fields"""
        return self.__set_separator__

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        expanded = expand_typing(cls, ModelValueError)

        cls.__fields__ = expanded['fields']
        cls.__record_fields__ = expanded['record_fields']
        cls.__doc__ = 'Initialise ``%s`` data model.' % cls.__name__

        cls.__unset_field__ = expanded['unset_field']
        cls.__empty_field__ = expanded['empty_field']
        cls.__set_separator__ = expanded['set_separator']

        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        init_args = collections.OrderedDict()

        field_names = list(self.__fields__)
        if len(args) > len(field_names):
            raise ModelTypeError('__init__() takes %d positional arguments but %d were given' % (len(field_names), len(args)))  # pylint: disable=line-too-long
        for index, arg in enumerate(args):
            name = field_names[index]
            init_args[name] = self.__fields__[name](arg)
        for arg, val in kwargs.items():
            if arg in init_args:
                raise ModelTypeError('__init__() got multiple values for argument %r' % arg)
            if arg not in field_names:
                if arg in self.__record_fields__ and isinstance(val, dict):
                    for arg_nam, arg_val in val.items():
                        name = '%s.%s' % (arg, arg_nam)
                        if name not in self.__fields__:
                            raise ModelTypeError('__init__() got an unexpected keyword argument %r' % name)
                        init_args[name] = self.__fields__[name](arg_val)
                    continue
                raise ModelTypeError('__init__() got an unexpected keyword argument %r' % arg)
            init_args[arg] = self.__fields__[arg](val)

        diff = list()
        for field in field_names:
            if field in init_args:
                continue
            diff.append(field)
        if diff:
            length = len(diff)
            if length == 1:
                diff_args = repr(diff[0])
            elif length == 2:
                diff_args = '%r and %r' % tuple(diff)
            else:
                diff_args = '%s, and %r' % (', '.join(map(repr, diff_args[:-1])), diff_args[-1])
            raise ModelTypeError('missing %d required positional arguments: %s' % (length, diff_args))

        for key, val in init_args.items():
            setattr(self, key, val)
        self.__post_init__()

    def __post_init__(self):
        """Post-processing customisation."""

    def __str__(self) -> str:
        fields = list()
        for field in self.__fields__:
            value = getattr(self, field)
            fields.append('%s=%s' % (field, value))
        return '%s(%s)' % (type(self).__name__, ', '.join(fields))

    def __repr__(self) -> str:
        fields = list()
        for field in self.__fields__:
            value = getattr(self, field)
            fields.append('%s=%s' % (field, value))
        return '%s(%s)' % (type(self).__name__, ', '.join(fields))

    def __call__(self, format: str) -> typing.Any:  # pylint: disable=redefined-builtin
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
        func = 'to%s' % format
        if hasattr(self, func):
            return getattr(self, func)()
        raise ModelFormatError('unsupported format: %s' % format)

    def tojson(self) -> typing.OrderedDict[str, typing.Any]:
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

    def toascii(self) -> typing.OrderedDict[str, str]:
        """Serialise data model as ASCII log format.

        Returns:
            An :obj:`OrderedDict` mapping each field and serialised text data.

        """
        fields = collections.OrderedDict()
        for field, type_cls in self.__fields__.items():
            value = getattr(self, field)
            fields[field] = type_cls.toascii(value)
        return fields

    def asdict(self, dict_factory: typing.Optional[type] = None) -> typing.Dict[str, typing.Any]:
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

    def astuple(self, tuple_factory: typing.Optional[type] = None) -> typing.Tuple[typing.Any]:
        """Convert data model as a tuple of field values.

        Args:
            tuple_factory: If given, ``tuple_factory`` will be used instead of
                built-in :obj:`tuple`.

        Returns:
            A tuple of field values.

        """
        fields = list()
        for field in self.__fields__:
            value = getattr(self, field)
            fields.append(value)

        if tuple_factory is None:
            tuple_factory = tuple
        return tuple_factory(fields)


def new_model(name: str, **fields: typing.Kwargs) -> Model:
    """Create a data model dynamically with the appropriate fields.

    Args:
        name: data model name
        **fields: defined fields of the data model

    Returns:
        :class:`Model`: created data model

    Examples:
        Typically, we define a data model by subclassing the :obj:`Model`
        class, as following::

            class MyLog(Model):
                field_one = StringType()
                field_two = SetType(element_type=PortType)

        when defining dynamically with :func:`new_model`, the definition above
        can be rewrote to::

            MyLog = new_model('MyLog', field_one=StringType(), field_two=SetType(element_type=PortType))

    """
    def gen_body(ns: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
        """Generate ``exec_body``."""
        for name, type_cls in fields.items():
            ns[name] = type_cls
    return types.new_class(name, (Model,), exec_body=gen_body)
