# -*- coding: utf-8 -*-
"""Bro/Zeek log loader."""

import abc
import dataclasses
import datetime
import json
import re
import warnings

import pandas

import blogging.typing as typing
from blogging.types import (AddrType, BoolType, CountType, DoubleType, EnumType, IntervalType,
                            IntType, PortType, SetType, StringType, SubnetType, TimeType, Type,
                            VectorType)

__all__ = [
    'ASCIIInfo', 'JSONInfo',
    'ASCIIParser', 'JSONParser',
]


def readline(file: typing.BinaryFile, separator: bytes = b'\x09') -> typing.List[bytes]:
    """Wrapper for ``readline`` function.

    Args:
        file: log file object opened in binary mode
        seperator: data separator

    """
    return file.readline().strip().split(separator)


class ParserError(ValueError):
    """Error when parsing logs.

    Attributes:
        msg: the unformatted error message
        field: the field name where parsing failed
        lineno: the line corresponding to the failure

    """

    def __init__(self, msg: str,
                 lineno: typing.Optional[int] = None,
                 field: typing.Optional[str] = None):
        """Initialisation.

        Args:
            msg: the unformatted error message
            lineno (:obj:`int`, optional): the line corresponding to the failure
            field (:obj:`str`, optional): the field name where parsing failed

        """
        if lineno is None:
            errmsg = msg
        elif field is None:
            errmsg = '%s: line %d' % (msg, lineno)
        else:
            errmsg = '%s: line %d (field %d)' % (msg, lineno, field)
        super().__init__(self, errmsg)

        self.msg = msg
        self.field = field
        self.lineno = lineno

    def __reduce__(self):
        return self.__class__, (self.msg, self.lineno, self.field)


class JSONParserError(ParserError, json.JSONDecodeError):
    """Error when parsing JSON log."""


class ASCIIPaserError(ParserError):
    """Error when parsing ASCII log."""


class ParserWarning(UserWarning):
    """Warning when parsing logs."""


class JSONParserWarning(ParserWarning):
    """Warning when parsing logs in JSON format."""


class Info:
    """Parsed log info."""

    @property
    @abc.abstractmethod
    def format(self):
        """str: Log file format."""


@dataclasses.dataclass(frozen=True)
class ASCIIInfo(Info):
    """Parsed log info for ASCII logs."""

    @property
    def format(self):
        """str: Log file format."""
        return 'ascii'

    path: str
    open: datetime.datetime
    close: datetime.datetime
    data: pandas.DataFrame
    exit_with_error: bool


@dataclasses.dataclass(frozen=True)
class JSONInfo(Info):
    """Parsed log info for JSON logs."""

    @property
    def format(self):
        """str: Log file format."""
        return 'json'

    data: pandas.DataFrame


class BaseParser(metaclass=abc.ABCMeta):
    """Basic log parser."""

    @property
    @abc.abstractmethod
    def format(self):
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
        fields (:obj:`Field`, optional): field declrations for
            :obj:`JSONParser`, as in JSON logs the field typing information are
            omitted by the Bro/Zeek Logging framework.

    """

    @property
    def format(self):
        return 'json'

    def __init__(self, fields=None):
        """Initialisation.

        Args:
            fields (:obj:`Field`, optional): field declarations for
                :obj:`JSONParser`, as in JSON logs the field typing information
                are omitted by the Bro/Zeek Logging framework.

        """
        if fields is None:
            warnings.warn('missing log fields data type declarations', JSONParserWarning)
        self.fields = fields

    def parse_file(self, file: typing.BinaryFile) -> JSONInfo:
        data = list()
        for index, line in enumerate(file, start=1):
            data.append(self.parse_line(line, lineno=index))
        return JSONInfo(
            data=pandas.DataFrame(data)
        )

    def parse_line(self, line: bytes, lineno: typing.Optional[int] = 0) -> dict:
        data: dict = json.loads(line)
        if self.fields is None:
            return data

        new_data = data.copy()
        for key, val in data.items():
            field = self.fields.get(key)
            if field is None:
                raise JSONParserError('unknown field', lineno, key)
            new_data[key] = field(val)
        return new_data


class ASCIIParser(BaseParser):
    """ASCII log parser.

    Attributes:
        type_hook (dict): Bro/Zeek type parsing hooks
        __type__ (:obj:`Dict[str, Type[Type]]`): Bro/Zeek type parser hooks
        enum_namespace (:obj:`Dict[str, Enum]`): global namespace for ``enum`` data type

    """

    @property
    def format(self):
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

        self.enum_namespace = enum_namespaces
        self.bare = bare

    def parse_file(self, file: typing.BinaryFile) -> ASCIIInfo:
        # data separator
        separator = file.readline().strip().split(b' ', maxsplit=1)[1].decode('unicode_escape').encode()
        # set seperator
        set_separator = readline(file, separator)[1]
        # empty field
        empty_field = readline(file, separator)[1]
        # unset field
        unset_field = readline(file, separator)[1]

        # log path
        path = readline(file, separator).encode()
        # log open time
        open_time = datetime.datetime.strptime(readline(file, separator)[1].encode(), r'%Y-%m-%d-%H-%M-%S')

        # log fields
        fields = file.readline().strip().decode().split(separator)[1:]
        # log filed types
        types = file.readline().strip().decode().split(separator)[1:]

        field_parser = list()
        for (field, type_) in zip(fields, types):
            match_set = re.match(r'set\[(?P<type>.+)\]', type_)
            if match_set is not None:
                set_type = match_set.group('type')
                type_cls = SetType(empty_field, unset_field, set_separator,
                                   element_type=self.__type__[set_type](empty_field, unset_field, set_separator))
                field_parser.append((field, type_cls))  # pylint: disable=cell-var-from-loop
                continue

            match_vector = re.match(r'^vector\[(.+?)\]', type_)
            if match_vector is not None:
                vector_type = match_vector.groups()[0]
                type_cls = VectorType(empty_field, unset_field, set_separator,
                                      element_type=self.__type__[vector_type](empty_field, unset_field, set_separator))
                field_parser.append((field, type_cls))  # pylint: disable=cell-var-from-loop
                continue

            if type_ == 'enum':
                type_cls = EnumType(empty_field, unset_field, set_separator,
                                    namespaces=self.enum_namespace, bare=self.bare)
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
            warnings.warn('log file exited with error', ParserWarning)
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
                   parser: typing.List[Type] = None) -> dict:
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
            data[field_name] = field_type(s)
        return data
