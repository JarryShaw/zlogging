# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports,unsubscriptable-object
"""Bro/Zeek log loader."""

import abc
import collections
import datetime
import io
import json
import re
import warnings
from typing import TYPE_CHECKING, TypeVar, cast

from zlogging._aux import readline
from zlogging._data import ASCIIInfo, JSONInfo
from zlogging._exc import (ASCIIParserWarning, ASCIIPaserError, JSONParserError, JSONParserWarning,
                   ParserError, ZeekValueError)
from zlogging.model import new_model
from zlogging.types import (AddrType, AnyType, BaseType, BoolType, CountType, DoubleType, EnumType,
                    IntervalType, IntType, PortType, SetType, StringType, SubnetType, TimeType,
                    VectorType)

__all__ = [
    'parse', 'parse_ascii', 'parse_json',
    'loads', 'loads_ascii', 'loads_json',
    'load', 'load_ascii', 'load_json',
    'ASCIIParser', 'JSONParser',
]

_S = TypeVar('_S', bound='_SimpleType')
if TYPE_CHECKING:
    from collections import OrderedDict
    from io import BufferedReader as BinaryFile
    from os import PathLike
    from typing import Any, Dict, List, Optional, Tuple, Type, Union

    from typing_extensions import Literal

    from ._data import Info
    from .model import Model
    from .types import _SimpleType

    AnyStr = Union[str, bytes]


class BaseParser(metaclass=abc.ABCMeta):
    """Basic log parser."""

    @property
    @abc.abstractmethod
    def format(self) -> str:
        """str: Log file format."""

    def parse(self, filename: 'PathLike[str]', model: 'Optional[Type[Model]]' = None) -> 'Info':
        """Parse log file.

        Args:
            filename: Log file name.
            model: Field declrations of current log.

        Returns:
            The parsed log as an :class:`~zlogging._data.ASCIIInfo` or :class:`~zlogging._data.JSONInfo`.

        """
        with open(filename, 'rb') as file:
            data = self.parse_file(file, model=model)  # type: ignore[arg-type]
        return data

    @abc.abstractmethod
    def parse_file(self, file: 'BinaryFile', model: 'Optional[Type[Model]]' = None) -> 'Info':
        """Parse log file.

        Args:
            file: Log file object opened in binary mode.
            model: Field declrations of current log.

        Returns:
            :class:`~zlogging._data.Info`: The parsed log as a :class:`~zlogging.model.Model` per line.

        """

    @abc.abstractmethod
    def parse_line(self, line: bytes, lineno: 'Optional[int]' = 0,
                   model: 'Optional[Type[Model]]' = None) -> 'Model':
        """Parse log line as one-line record.

        Args:
            line: A simple line of log.
            lineno: Line number of current line.
            model: Field declrations of current log.

        Returns:
            The parsed log as a plain :class:`~zlogging.model.Model`.

        """

    def load(self, file: 'BinaryFile') -> 'Info':
        """Parse log file.

        Args:
            file: Log file object opened in binary mode.

        Returns:
            :class:`~zlogging._data.Info`: The parsed log as a :class:`~zlogging.model.Model` per line.

        """
        return self.parse_file(file)

    def loads(self, line: bytes, lineno: 'Optional[int]' = 0) -> 'Model':
        """Parse log line as one-line record.

        Args:
            line: A simple line of log.
            lineno: Line number of current line.

        Returns:
            The parsed log as a plain :class:`~zlogging.model.Model`.

        """
        return self.parse_line(line, lineno)


class JSONParser(BaseParser):
    """JSON log parser.

    Args:
        model (:class:`~zlogging.model.Model` class, optional): Field
            declrations for :class:`~zlogging.loader.JSONParser`, as in JSON
            logs the field typing information are omitted by the Bro/Zeek
            logging framework.

    Attributes:
        model (:class:`~zlogging.model.Model` class, optional): Field
            declrations for :class:`~zlogging.loader.JSONParser`, as in JSON
            logs the field typing information are omitted by the Bro/Zeek
            logging framework.

    Warns:
        JSONParserWarning: If ``model`` is not specified.

    """

    @property
    def format(self) -> 'Literal["json"]':
        """str: Log file format."""
        return 'json'

    def __init__(self, model: 'Optional[Type[Model]]' = None):
        if model is None:
            warnings.warn('missing log data model specification', JSONParserWarning)
        self.model = model

    if TYPE_CHECKING:
        def parse(self, filename: 'PathLike[str]', model: 'Optional[Type[Model]]' = None) -> 'JSONInfo':  # pylint: disable=signature-differs,line-too-long
            ...

    def parse_file(self, file: 'BinaryFile', model: 'Optional[Type[Model]]' = None) -> 'JSONInfo':
        """Parse log file.

        Args:
            file: Log file object opened in binary mode.
            model: Field declrations of current log.

        Returns:
            :class:`~zlogging._data.JSONInfo`: The parsed log as a
                :class:`~zlogging.model.Model` per line.

        """
        data = list()
        for index, line in enumerate(file, start=1):
            data.append(self.parse_line(line, lineno=index, model=model))
        return JSONInfo(
            data=data
        )

    def parse_line(self, line: bytes, lineno: 'Optional[int]' = 0,
                   model: 'Optional[Type[Model]]' = None) -> 'Model':
        """Parse log line as one-line record.

        Args:
            line: A simple line of log.
            lineno: Line number of current line.
            model: Field declrations of current log.

        Returns:
            The parsed log as a plain :class:`~zlogging.model.Model`.

        Raises:
            :exc:`JSONParserError`: If failed to serialise the ``line`` from JSON.

        """
        try:
            data = json.loads(line)  # type: Dict[str, Any]
        except json.JSONDecodeError as error:
            raise JSONParserError(error.msg, lineno) from error

        model_cls = model or self.model
        if model_cls is None:
            model_cls = new_model('<unknown>', **{field: AnyType() for field in data.keys()})
        return model_cls(**data)


class ASCIIParser(BaseParser):
    """ASCII log parser.

    Args:
        type_hook (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` class, optional):
            Bro/Zeek type parser hooks. User may customise subclasses of
            :class:`~zlogging.types.BaseType` to modify parsing behaviours.
        enum_namespaces (:obj:`List[str]`, optional): Namespaces to be loaded.
        bare (:obj:`bool`, optional): If ``True``, do not load ``zeek`` namespace by default.

    Attributes:
        __type__ (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` class):
            Bro/Zeek type parser hooks.
        enum_namespaces (:obj:`List[str]`): Namespaces to be loaded.
        bare (bool): If ``True``, do not load ``zeek`` namespace by default.

    """

    @property
    def format(self) -> 'Literal["ascii"]':
        """str: Log file format."""
        return 'ascii'

    def __init__(self, type_hook: 'Optional[Dict[str, Type[BaseType]]]' = None,
                 enum_namespaces: 'Optional[List[str]]' = None, bare: bool = False) -> None:
        self.__type__ = {
            'bool': BoolType,
            'count': CountType,
            'int': IntType,
            'double': DoubleType,
            'time': TimeType,
            'interval': IntervalType,
            'string': StringType,
            'addr': AddrType,
            'port': PortType,
            'subnet': SubnetType,
            'enum': EnumType,
            'set': SetType,
            'vector': VectorType,
          }  # type: Dict[str, Type[BaseType]]
        if type_hook is not None:
            self.__type__.update(type_hook)

        self.enum_namespaces = enum_namespaces
        self.bare = bare

    if TYPE_CHECKING:
        def parse(self, filename: 'PathLike[str]', model: 'Optional[Type[Model]]' = None) -> 'ASCIIInfo':  # pylint: disable=signature-differs,line-too-long
            ...

    def parse_file(self, file: 'BinaryFile', model: 'Optional[Type[Model]]' = None) -> 'ASCIIInfo':
        """Parse log file.

        Args:
            file: Log file object opened in binary mode.
            model: Field declrations of current log. This parameter is
                only kept for API compatibility with its base class
                :class:`~zlogging.loader.BaseLoader`, and will **NOT**
                be used at runtime.

        Returns:
            :class:`~zlogging._data.ASCIIInfo`: The parsed log as a
                :class:`~zlogging.model.Model` per line.

        Warns:
            ASCIIParserWarning: If the ASCII log file exited with error, see
                :attr:`ASCIIInfo.exit_with_error <zlogging._data.ASCIIInfo.exit_with_error>`
                for more information.

        """
        # data separator
        separator = readline(file, b' ', maxsplit=1)[1].decode('unicode_escape').encode('ascii')
        # set separator
        set_separator = readline(file, separator, maxsplit=1)[1]
        # empty field
        empty_field = readline(file, separator, maxsplit=1)[1]
        # unset field
        unset_field = readline(file, separator, maxsplit=1)[1]

        # log path
        path = readline(file, separator, maxsplit=1, decode=True)[1]
        # log open time
        open_time = datetime.datetime.strptime(readline(file, separator, maxsplit=1, decode=True)[1],
                                               r'%Y-%m-%d-%H-%M-%S')

        # log model
        model_line = readline(file, separator, decode=True)[1:]
        # log filed types
        types_line = readline(file, separator, decode=True)[1:]

        field_parser = []  # type: List[Tuple[str, BaseType]]
        model_fields = collections.OrderedDict()
        for (field, type_) in zip(model_line, types_line):
            match_set = re.match(r'set\[(?P<type>.+?)\]', type_)
            if match_set is not None:
                set_type = match_set.group('type')
                ele_type = cast('Type[_SimpleType]', self.__type__[set_type])
                type_cls = SetType(empty_field, unset_field, set_separator,
                                   element_type=ele_type(empty_field, unset_field, set_separator))
                field_parser.append((field, type_cls))
                model_fields[field] = type_cls
                continue

            match_vector = re.match(r'^vector\[(?P<type>.+?)\]', type_)
            if match_vector is not None:
                vec_type = match_vector.group('type')
                ele_type = cast('Type[_SimpleType]', self.__type__[vec_type])
                type_cls = VectorType(empty_field, unset_field, set_separator,
                                      element_type=ele_type(empty_field, unset_field, set_separator))  # type: ignore[assignment] # pylint: disable=line-too-long
                field_parser.append((field, type_cls))
                model_fields[field] = type_cls
                continue

            if type_ == 'enum':
                type_cls = EnumType(empty_field, unset_field, set_separator,
                                    namespaces=self.enum_namespaces, bare=self.bare)  # type: ignore[assignment]
                field_parser.append((field, type_cls))
                model_fields[field] = type_cls
                continue

            ele_type = cast('Type[_SimpleType]', self.__type__[type_])
            type_cls = ele_type(empty_field, unset_field, set_separator)  # type: ignore[assignment]
            field_parser.append((field, type_cls))
            model_fields[field] = type_cls
        model_cls = new_model(path, **model_fields)

        if TYPE_CHECKING:
            close_time = datetime.datetime.now()

        exit_with_error = True
        data = list()
        for index, line in enumerate(file, start=1):
            if line.startswith(b'#'):
                exit_with_error = False
                close_time = datetime.datetime.strptime(line.strip().split(separator)[1].decode(),
                                                        r'%Y-%m-%d-%H-%M-%S')
                break

            parsed = self.parse_line(line, lineno=index, model=model_cls, parser=field_parser)
            data.append(parsed)

        if exit_with_error:
            warnings.warn('log file exited with error', ASCIIParserWarning)
            close_time = datetime.datetime.now()

        return ASCIIInfo(
            path=cast('PathLike[str]', path),
            open=open_time,
            close=close_time,
            data=data,
            exit_with_error=exit_with_error,
        )

    def parse_line(self, line: bytes, lineno: 'Optional[int]' = 0,  # pylint: disable=arguments-differ
                   model: 'Optional[Type[Model]]' = None, separator: 'Optional[bytes]' = b'\x09',
                   parser: 'Optional[List[Tuple[str, BaseType]]]' = None) -> 'Model':
        """Parse log line as one-line record.

        Args:
            line: A simple line of log.
            lineno: Line number of current line.
            model: Field declrations of current log.
            separator: Data separator.
            parser (:obj:`List` of :class:`~zlogging.types.BaseType`, required): Field data type parsers.

        Returns:
            The parsed log as a plain :obj:`dict`.

        Raises:
            :exc:`ASCIIPaserError`: If ``parser`` is not provided; or failed to
                serialise ``line`` as ASCII.

        """
        if parser is None:
            raise ASCIIPaserError("parse_line() missing 1 required positional argument: 'parser'")

        data = collections.OrderedDict()  # type: OrderedDict[str, Any]
        for i, s in enumerate(line.strip().split(separator)):
            field_name, field_type = parser[i]
            try:
                data[field_name] = field_type(s)
            except ZeekValueError as error:
                raise ASCIIPaserError(str(error), lineno, field_name) from error

        if model is None:
            model = new_model('<unknown>', **{field: AnyType() for field in data.keys()})
        return model(**data)


def parse_json(filename: 'PathLike[str]',  # pylint: disable=unused-argument,keyword-arg-before-vararg
               parser: 'Optional[Type[JSONParser]]' = None,
               model: 'Optional[Type[Model]]' = None,
               *args: 'Any', **kwargs: 'Any') -> JSONInfo:
    """Parse JSON log file.

    Args:
        filename: Log file name.
        parser (:class:`~zlogging.loader.JSONParser`, optional): Parser class.
        model (:class:`~zlogging.models.Model` class, optional): Field
            declarations for :class:`~zlogging.loader.JSONParser`, as in JSON
            logs the field typing information are omitted by the Bro/Zeek
            logging framework.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The parsed JSON log data.

    """
    if parser is None:
        parser = JSONParser
    json_parser = parser(model)
    return json_parser.parse(filename)


def load_json(file: 'BinaryFile',  # pylint: disable=unused-argument,keyword-arg-before-vararg
              parser: 'Optional[Type[JSONParser]]' = None,
              model: 'Optional[Type[Model]]' = None,
              *args: 'Any', **kwargs: 'Any') -> JSONInfo:
    """Parse JSON log file.

    Args:
        file: Log file object opened in binary mode.
        parser (:class:`~zlogging.loader.JSONParser`, optional): Parser class.
        model (:class:`~zlogging.models.Model` class, optional): Field
            declarations for :class:`~zlogging.loader.JSONParser`, as in JSON
            logs the field typing information are omitted by the Bro/Zeek
            logging framework.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The parsed JSON log data.

    """
    if parser is None:
        parser = JSONParser
    json_parser = parser(model)
    return json_parser.parse_file(file)


def loads_json(data: 'AnyStr',  # pylint: disable=unused-argument,keyword-arg-before-vararg
               parser: 'Optional[Type[JSONParser]]' = None,
               model: 'Optional[Type[Model]]' = None,
               *args: 'Any', **kwargs: 'Any') -> JSONInfo:
    """Parse JSON log string.

    Args:
        data: Log string as binary or encoded string.
        parser (:class:`~zlogging.loader.JSONParser`, optional): Parser class.
        model (:class:`~zlogging.models.Model` class, optional): Field
            declarations for :class:`~zlogging.loader.JSONParser`, as in JSON
            logs the field typing information are omitted by the Bro/Zeek
            logging framework.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The parsed JSON log data.

    """
    if isinstance(data, str):
        data = data.encode('ascii')

    if parser is None:
        parser = JSONParser
    json_parser = parser(model)

    with io.BytesIO(data) as file:
        info = json_parser.parse_file(file)  # type: ignore[arg-type]
    return info


def parse_ascii(filename: 'PathLike[str]',  # pylint: disable=unused-argument,keyword-arg-before-vararg
                parser: 'Optional[Type[ASCIIParser]]' = None,
                type_hook: 'Optional[Dict[str, Type[BaseType]]]' = None,
                enum_namespaces: 'Optional[List[str]]' = None, bare: bool = False,
                *args: 'Any', **kwargs: 'Any') -> 'ASCIIInfo':
    """Parse ASCII log file.

    Args:
        filename: Log file name.
        parser (:class:`~zlogging.loader.ASCIIParser`, optional): Parser class.
        type_hook (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` class, optional):
            Bro/Zeek type parser hooks. User may customise subclasses of
            :class:`~zlogging.types.BaseType` to modify parsing behaviours.
        enum_namespaces (:obj:`List[str]`, optional): Namespaces to be loaded.
        bare (:obj:`bool`, optional): If ``True``, do not load ``zeek`` namespace by default.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The parsed ASCII log data.

    """
    if parser is None:
        parser = ASCIIParser
    ascii_parser = parser(type_hook, enum_namespaces, bare)
    return ascii_parser.parse(filename)


def load_ascii(file: 'BinaryFile',  # pylint: disable=unused-argument,keyword-arg-before-vararg
               parser: 'Optional[Type[ASCIIParser]]' = None,
               type_hook: 'Optional[Dict[str, Type[BaseType]]]' = None,
               enum_namespaces: 'Optional[List[str]]' = None, bare: bool = False,
               *args: 'Any', **kwargs: 'Any') -> 'ASCIIInfo':
    """Parse ASCII log file.

    Args:
        file: Log file object opened in binary mode.
        parser (:class:`~zlogging.loader.ASCIIParser`, optional): Parser class.
        type_hook (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` class, optional):
            Bro/Zeek type parser hooks. User may customise subclasses of
            :class:`~zlogging.types.BaseType` to modify parsing behaviours.
        enum_namespaces (:obj:`List[str]`, optional): Namespaces to be loaded.
        bare (:obj:`bool`, optional): If ``True``, do not load ``zeek`` namespace by default.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The parsed ASCII log data.

    """
    if parser is None:
        parser = ASCIIParser
    ascii_parser = parser(type_hook, enum_namespaces, bare)
    return ascii_parser.parse_file(file)


def loads_ascii(data: 'AnyStr',  # pylint: disable=unused-argument,keyword-arg-before-vararg
                parser: 'Optional[Type[ASCIIParser]]' = None,
                type_hook: 'Optional[Dict[str, Type[BaseType]]]' = None,
                enum_namespaces: 'Optional[List[str]]' = None, bare: bool = False,
                *args: 'Any', **kwargs: 'Any') -> 'ASCIIInfo':
    """Parse ASCII log string.

    Args:
        data: Log string as binary or encoded string.
        parser (:class:`~zlogging.loader.ASCIIParser`, optional): Parser class.
        type_hook (:obj:`dict` mapping :obj:`str` and :class:`~zlogging.types.BaseType` class, optional):
            Bro/Zeek type parser hooks. User may customise subclasses of
            :class:`~zlogging.types.BaseType` to modify parsing behaviours.
        enum_namespaces (:obj:`List[str]`, optional): Namespaces to be loaded.
        bare (:obj:`bool`, optional): If ``True``, do not load ``zeek`` namespace by default.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The parsed ASCII log data.

    """
    if isinstance(data, str):
        data = data.encode('ascii')

    if parser is None:
        parser = ASCIIParser
    ascii_parser = parser(type_hook, enum_namespaces, bare)

    with io.BytesIO(data) as file:
        info = ascii_parser.parse_file(file)  # type: ignore[arg-type]
    return info


def parse(filename: 'PathLike[str]', *args: 'Any', **kwargs: 'Any') -> 'Union[JSONInfo, ASCIIInfo]':
    """Parse Bro/Zeek log file.

    Args:
        filename: Log file name.
        *args: See :func:`~zlogging.loader.parse_json` and
            :func:`~zlogging.loader.parse_ascii` for more information.
        **kwargs: See :func:`~zlogging.loader.parse_json` and
            :func:`~zlogging.loader.parse_ascii` for more information.

    Returns:
        The parsed JSON log data.

    Raises:
        :exc:`ParserError`: If the format of the log file is unknown.

    """
    with open(filename, 'rb') as file:
        char = file.read(1)

    if char == b'#':
        return parse_ascii(filename, *args, **kwargs)
    if char == b'{':
        return parse_json(filename, *args, **kwargs)
    raise ParserError('unknown format')


def load(file: 'BinaryFile', *args: 'Any', **kwargs: 'Any') -> 'Union[JSONInfo, ASCIIInfo]':
    """Parse Bro/Zeek log file.

    Args:
        file: Log file object opened in binary mode.
        *args: See :func:`~zlogging.loader.load_json` and
            :func:`~zlogging.loader.load_ascii` for more information.
        **kwargs: See :func:`~zlogging.loader.load_json` and
            :func:`~zlogging.loader.load_ascii` for more information.

    Returns:
        The parsed JSON log data.

    Raises:
        :exc:`ParserError`: If the format of the log file is unknown.

    """
    tell = file.tell()
    char = file.read(1)
    file.seek(tell, io.SEEK_SET)

    if char == b'#':
        return load_ascii(file, *args, **kwargs)
    if char == b'{':
        return load_json(file, *args, **kwargs)
    raise ParserError('unknown format')


def loads(data: 'AnyStr', *args: 'Any', **kwargs: 'Any') -> 'Union[JSONInfo, ASCIIInfo]':
    """Parse Bro/Zeek log string.

    Args:
        data: Log string as binary or encoded string.
        *args: See :func:`~zlogging.loader.loads_json` and
            :func:`~zlogging.loader.loads_ascii` for more information.
        **kwargs: See :func:`~zlogging.loader.loads_json` and
            :func:`~zlogging.loader.loads_ascii` for more information.

    Returns:
        The parsed JSON log data.

    Raises:
        :exc:`ParserError`: If the format of the log file is unknown.

    """
    if isinstance(data, str):
        data = data.encode('ascii')

    if data.startswith(b'#'):
        return loads_ascii(data, *args, **kwargs)
    if data.startswith(b'{'):
        return loads_json(data, *args, **kwargs)
    raise ParserError('unknown format')
