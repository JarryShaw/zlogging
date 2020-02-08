# -*- coding: utf-8 -*-
"""Bro/Zeek log loader."""

import abc
import datetime
import io
import json
import re
import warnings

import pandas

import blogging._typing as typing
from blogging._aux import readline
from blogging._data import ASCIIInfo, Info, JSONInfo
from blogging._exc import (ASCIIParserWarning, ASCIIPaserError, JSONParserError, JSONParserWarning,
                           ParserError)
from blogging.model import Model
from blogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                            IntType, PortType, SetType, StringType, SubnetType, TimeType, Type,
                            VectorType, ZeekValueError)

__all__ = [
    'parse', 'parse_ascii', 'parse_json',
    'loads', 'loads_ascii', 'loads_json',
    'load', 'load_ascii', 'load_json',
    'ASCIIParser', 'JSONParser',
]


class BaseParser(metaclass=abc.ABCMeta):
    """Basic log parser."""

    @property
    @abc.abstractmethod
    def format(self) -> str:
        """str: Log file format."""

    def parse(self, filename: typing.PathLike) -> Info:
        """Parse log file.

        Args:
            filename: log file name

        Returns:
            The parsed log as an :obj:`ASCIIInfo` or :obj:`JSONInfo`.

        """
        with open(filename, 'rb') as file:
            data = self.parse_file(file)
        return data

    @abc.abstractmethod
    def parse_file(self, file: typing.BinaryFile) -> Info:
        """Parse log file.

        Args:
            file: log file object opened in binary mode

        Returns:
            Info: The parsed log as a :obj:`pandas.DataFrame` per line.

        """

    @abc.abstractmethod
    def parse_line(self, line: bytes, lineno: typing.Optional[int] = 0) -> dict:
        """Parse log line as one-line record.

        Args:
            line: a simple line of log
            lineno: line number of current line

        Returns:
            The parsed log as a :obj:`dict`.

        """


class JSONParser(BaseParser):
    """JSON log parser.

    Attributes:
        model (:obj:`Model` class, optional): field declrations for
            :obj:`JSONParser`, as in JSON logs the field typing information are
            omitted by the Bro/Zeek Logging framework.

    """

    @property
    def format(self) -> str:
        """str: Log file format."""
        return 'json'

    def __init__(self, model: typing.Optional[typing.Type[Model]] = None):
        """Initialisation.

        Args:
            model (:obj:`Model` class, optional): field declarations for
                :obj:`JSONParser`, as in JSON logs the field typing information
                are omitted by the Bro/Zeek Logging framework.

        """
        if model is None:
            warnings.warn('missing log model data type declarations', JSONParserWarning)
        self.model = model

    def parse_file(self, file: typing.BinaryFile) -> JSONInfo:
        """Parse log file.

        Args:
            file: log file object opened in binary mode

        Returns:
            Info: The parsed log as a :obj:`pandas.DataFrame` per line.

        """
        data = list()
        for index, line in enumerate(file, start=1):
            data.append(self.parse_line(line, lineno=index))
        return JSONInfo(
            data=pandas.DataFrame(data)
        )

    def parse_line(self, line: bytes, lineno: typing.Optional[int] = 0) -> dict:
        """Parse log line as one-line record.

        Args:
            line: a simple line of log
            lineno: line number of current line

        Returns:
            The parsed log as a :obj:`dict`.

        """
        try:
            data: dict = json.loads(line)
        except json.JSONDecodeError as error:
            raise JSONParserError(error.msg, lineno)
        if self.model is None:
            return data

        new_data = data.copy()
        for key, val in data.items():
            field = getattr(self.model, key, None)
            if not hasattr(self.model, key):
                raise JSONParserError('unknown field', lineno, key)
            field = getattr(self.model, key)
            new_data[key] = field(val)
        return new_data


class ASCIIParser(BaseParser):
    """ASCII log parser.

    Attributes:
        type_hook (dict): Bro/Zeek type parsing hooks
        __type__ (:obj:`Dict[str, Type[Type]]`): Bro/Zeek type parser hooks
        enum_namespaces (:obj:`Dict[str, Enum]`): global namespace for ``enum`` data type

    """

    @property
    def format(self) -> str:
        """str: Log file format."""
        return 'ascii'

    def __init__(self, type_hook: typing.Optional[typing.Dict[str, typing.Type[Type]]] = None,
                 enum_namespaces: typing.Optional[typing.List[str]] = None, bare: bool = False):
        """Initialisation.

        Args:
            type_hook (:obj:`Dict[str, Type[Type]]`, optional): Bro/Zeek type
                parser hooks. User may customise subclasses of :obj:`Type` to
                modify parsing behaviours.
            enum_namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            bare (:obj:`bool`, optional): if ``True``, do not load ``zeek`` namespace by default

        """
        self.__type__: typing.Dict[str, typing.Type[Type]] = dict(
            bool=BoolType,
            count=CountType,
            int=IntType,
            double=DoubleType,
            time=TimeType,
            interval=IntervalType,
            string=StringType,
            addr=AddrType,
            port=PortType,
            subnet=SubnetType,
            enum=EnumType,
            set=SetType,
            vector=VectorType,
        )
        if type_hook is not None:
            self.__type__.update(type_hook)

        self.enum_namespaces = enum_namespaces
        self.bare = bare

    def parse_file(self, file: typing.BinaryFile) -> ASCIIInfo:
        """Parse log file.

        Args:
            file: log file object opened in binary mode

        Returns:
            Info: The parsed log as a :obj:`pandas.DataFrame` per line.

        """
        # data separator
        separator = readline(file, b' ', maxsplit=1)[1].decode('unicode_escape').encode('ascii')
        # set seperator
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
        model = readline(file, separator, decode=True)[1:]
        # log filed types
        types = readline(file, separator, decode=True)[1:]

        field_parser = list()
        for (field, type_) in zip(model, types):
            match_set = re.match(r'set\[(?P<type>.+?)\]', type_)
            if match_set is not None:
                set_type = match_set.group('type')
                type_cls = SetType(empty_field, unset_field, set_separator,
                                   element_type=self.__type__[set_type](empty_field, unset_field, set_separator))
                field_parser.append((field, type_cls))
                continue

            match_vector = re.match(r'^vector\[(?P<type>.+?)\]', type_)
            if match_vector is not None:
                vector_type = match_vector.group('type')
                type_cls = VectorType(empty_field, unset_field, set_separator,
                                      element_type=self.__type__[vector_type](empty_field, unset_field, set_separator))
                field_parser.append((field, type_cls))
                continue

            if type_ == 'enum':
                type_cls = EnumType(empty_field, unset_field, set_separator,
                                    namespaces=self.enum_namespaces, bare=self.bare)
                field_parser.append((field, type_cls))
                continue

            type_cls = self.__type__[type_](empty_field, unset_field, set_separator)
            field_parser.append((field, type_cls))

        exit_with_error = True
        data = list()
        for index, line in enumerate(file, start=1):
            if line.startswith(b'#'):
                exit_with_error = False
                close_time = datetime.datetime.strptime(line.strip().split(separator)[1].decode(),
                                                        r'%Y-%m-%d-%H-%M-%S')
                break
            data.append(self.parse_line(line, lineno=index, parser=field_parser))

        if exit_with_error:
            warnings.warn('log file exited with error', ASCIIParserWarning)
            close_time = datetime.datetime.now()

        return ASCIIInfo(
            path=path,
            open=open_time,
            close=close_time,
            context=pandas.DataFrame(data),
            exit_with_error=exit_with_error,
        )

    def parse_line(self, line, lineno=0,  # pylint: disable=arguments-differ
                   separator: typing.Optional[bytes] = b'\x09',
                   parser: typing.List[typing.Tuple[str, Type]] = None) -> dict:
        """Parse log line as one-line record.

        Args:
            line: a simple line of log
            lineno: line number of current line
            separator: data separator
            parser (:obj:`List[Type]`, required): field data type parsers

        Returns:
            The parsed log as a :obj:`dict`.

        """
        if parser is None:
            raise ASCIIPaserError("parse_line() missing 1 required positional argument: 'parser'")

        data = dict()
        for i, s in enumerate(line.strip().split(separator)):
            field_name, field_type = parser[i]
            try:
                data[field_name] = field_type(s)
            except ZeekValueError as error:
                raise ASCIIPaserError(str(error), lineno, field_name)
        return data


def parse_json(filename: typing.PathLike,
               parser: typing.Optional[typing.Type[JSONParser]] = None,
               model: typing.Optional[typing.Type[Model]] = None) -> JSONInfo:
    """Parse JSON log file.

    Args:
        filename: log file name
        parser (:obj:`JSONParser`, optional): parser class
        model (:obj:`Model` class, optional): field declarations for
            :obj:`JSONParser`, as in JSON logs the field typing information are
            omitted by the Bro/Zeek Logging framework.

    Returns:
        The parsed JSON log data.

    """
    if parser is None:
        parser = JSONParser
    json_parser = parser(model)
    return json_parser.parse(filename)


def load_json(file: typing.BinaryFile,
              parser: typing.Optional[typing.Type[JSONParser]] = None,
              model: typing.Optional[typing.Type[Model]] = None) -> JSONInfo:
    """Parse JSON log file.

    Args:
        file: log file object opened in binary mode
        parser (:obj:`JSONParser`, optional): parser class
        model (:obj:`Model` class, optional): field declarations for
            :obj:`JSONParser`, as in JSON logs the field typing information are
            omitted by the Bro/Zeek Logging framework.

    Returns:
        The parsed JSON log data.

    """
    if parser is None:
        parser = JSONParser
    json_parser = parser(model)
    return json_parser.parse_file(file)


def loads_json(data: typing.AnyStr,
               parser: typing.Optional[typing.Type[JSONParser]] = None,
               model: typing.Optional[typing.Type[Model]] = None) -> JSONInfo:
    """Parse JSON log string.

    Args:
        data: log string as binary or encoded string
        parser (:obj:`JSONParser`, optional): parser class
        model (:obj:`Model` class, optional): field declarations for
            :obj:`JSONParser`, as in JSON logs the field typing information are
            omitted by the Bro/Zeek Logging framework.

    Returns:
        The parsed JSON log data.

    """
    if isinstance(data, str):
        data = data.encode('ascii')

    if parser is None:
        parser = JSONParser
    json_parser = parser(model)

    with io.BytesIO(data) as file:
        info = json_parser.parse_file(file)
    return info


def parse_ascii(filename: typing.PathLike,
                parser: typing.Optional[typing.Type[ASCIIInfo]] = None,
                type_hook: typing.Optional[typing.Dict[str, typing.Type[Type]]] = None,
                enum_namespaces: typing.Optional[typing.List[str]] = None, bare: bool = False) -> ASCIIInfo:
    """Parse ASCII log file.

    Args:
        filename: log file name
        parser (:obj:`ASCIIParser`, optional): parser class
        type_hook (:obj:`Dict[str, Type[Type]]`, optional): Bro/Zeek type
                parser hooks. User may customise subclasses of :obj:`Type` to
                modify parsing behaviours.
            enum_namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            bare (:obj:`bool`, optional): if ``True``, do not load ``zeek`` namespace by default

    Returns:
        The parsed ASCII log data.

    """
    if parser is None:
        parser = ASCIIParser
    ascii_parser = parser(type_hook, enum_namespaces, bare)
    return ascii_parser.parse(filename)


def load_ascii(file: typing.BinaryFile,
               parser: typing.Optional[typing.Type[ASCIIInfo]] = None,
               type_hook: typing.Optional[typing.Dict[str, typing.Type[Type]]] = None,
               enum_namespaces: typing.Optional[typing.List[str]] = None, bare: bool = False) -> ASCIIInfo:
    """Parse ASCII log file.

    Args:
        file: log file object opened in binary mode
        parser (:obj:`ASCIIParser`, optional): parser class
        type_hook (:obj:`Dict[str, Type[Type]]`, optional): Bro/Zeek type
                parser hooks. User may customise subclasses of :obj:`Type` to
                modify parsing behaviours.
            enum_namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            bare (:obj:`bool`, optional): if ``True``, do not load ``zeek`` namespace by default

    Returns:
        The parsed ASCII log data.

    """
    if parser is None:
        parser = ASCIIParser
    ascii_parser = parser(type_hook, enum_namespaces, bare)
    return ascii_parser.parse_file(file)


def loads_ascii(data: typing.AnyStr,
                parser: typing.Optional[typing.Type[ASCIIInfo]] = None,
                type_hook: typing.Optional[typing.Dict[str, typing.Type[Type]]] = None,
                enum_namespaces: typing.Optional[typing.List[str]] = None, bare: bool = False) -> ASCIIInfo:
    """Parse ASCII log string.

    Args:
        data: log string as binary or encoded string
        parser (:obj:`ASCIIParser`, optional): parser class
        type_hook (:obj:`Dict[str, Type[Type]]`, optional): Bro/Zeek type
                parser hooks. User may customise subclasses of :obj:`Type` to
                modify parsing behaviours.
            enum_namespaces (:obj:`List[str]`, optional): namespaces to be loaded
            bare (:obj:`bool`, optional): if ``True``, do not load ``zeek`` namespace by default

    Returns:
        The parsed ASCII log data.

    """
    if isinstance(data, str):
        data = data.encode('ascii')

    if parser is None:
        parser = ASCIIParser
    ascii_parser = parser(type_hook, enum_namespaces, bare)

    with io.BytesIO(data) as file:
        info = ascii_parser.parse_file(file)
    return info


def parse(filename: typing.PathLike,
          *args: typing.Args, **kwargs: typing.Kwargs) -> typing.Union[JSONInfo, ASCIIInfo]:
    """Parse Bro/Zeek log file.

    Args:
        filename: log file name
        *args: see :func:`parse_json` and :func:`parse_ascii` for more information
        **kwargs: see :func:`parse_json` and :func:`parse_ascii` for more information

    Returns:
        The parsed JSON log data.

    """
    with open(filename, 'rb') as file:
        char = file.read(1)

    if char == b'#':
        return parse_ascii(filename, *args, **kwargs)
    if char == b'{':
        return parse_json(filename, *args, **kwargs)
    raise ParserError('unknown format')


def load(file: typing.BinaryFile,
         *args: typing.Args, **kwargs: typing.Kwargs) -> typing.Union[JSONInfo, ASCIIInfo]:
    """Parse Bro/Zeek log file.

    Args:
        file: log file object opened in binary mode
        *args: see :func:`parse_json` and :func:`parse_ascii` for more information
        **kwargs: see :func:`parse_json` and :func:`parse_ascii` for more information

    Returns:
        The parsed JSON log data.

    """
    tell = file.tell()
    char = file.read(1)
    file.seek(tell, io.SEEK_SET)

    if char == b'#':
        return load_ascii(file, *args, **kwargs)
    if char == b'{':
        return load_json(file, *args, **kwargs)
    raise ParserError('unknown format')


def loads(data: typing.AnyStr,
          *args: typing.Args, **kwargs: typing.Kwargs) -> typing.Union[JSONInfo, ASCIIInfo]:
    """Parse Bro/Zeek log string.

    Args:
        data: log string as binary or encoded string
        *args: see :func:`parse_json` and :func:`parse_ascii` for more information
        **kwargs: see :func:`parse_json` and :func:`parse_ascii` for more information

    Returns:
        The parsed JSON log data.

    """
    if isinstance(data, str):
        data = data.encode('ascii')

    if data.startswith(b'#'):
        return loads_ascii(data, *args, **kwargs)
    if data.startswith(b'{'):
        return loads_json(data, *args, **kwargs)
    raise ParserError('unknown format')
