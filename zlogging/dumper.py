# -*- coding: utf-8 -*-
"""Bro/Zeek log dumper."""

import abc
import json
import os
import time
from typing import TYPE_CHECKING

from zlogging._aux import unicode_escape
from zlogging._exc import ASCIIWriterError, JSONWriterError, WriterFormatError
from zlogging.model import Model

__all__ = [
    'write', 'write_ascii', 'write_json',
    'dumps', 'dumps_ascii', 'dumps_json',
    'dump', 'dump_ascii', 'dump_json',
    'ASCIIWriter', 'JSONWriter',
]

if TYPE_CHECKING:
    from io import TextIOWrapper as TextFile
    from json import JSONEncoder
    from os import PathLike
    from typing import Any, Iterable, Literal, Optional, Type, Union

    AnyStr = Union[str, bytes]


class BaseWriter(metaclass=abc.ABCMeta):
    """Basic log writer."""

    @property
    @abc.abstractmethod
    def format(self) -> str:
        """Log file format."""

    def write(self, filename: 'PathLike[str]', data: 'Iterable[Model]') -> 'int':
        """Write log file.

        Args:
            filename: Log file name.
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The file offset after writing.

        """
        with open(filename, 'w', encoding='ascii') as file:
            offset = self.write_file(file, data)
        return offset

    @abc.abstractmethod
    def write_file(self, file: 'TextFile', data: 'Iterable[Model]') -> 'int':
        """Write log file.

        Args:
            file: Log file object opened in text mode.
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The file offset after writing.

        """

    @abc.abstractmethod
    def write_line(self, file: 'TextFile', data: 'Model',
                   lineno: 'Optional[int]' = 0) -> 'int':
        """Write log line as one-line record.

        Args:
            file: Log file object opened in text mode.
            data: Log record.
            lineno: Line number of current line.

        Returns:
            The file offset after writing.

        """

    @abc.abstractmethod
    def dump_file(self, data: 'Iterable[Model]') -> 'str':
        """Serialise records to a log line.

        Args:
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The converted log string.

        """

    @abc.abstractmethod
    def dump_line(self, data: 'Model', lineno: 'Optional[int]' = 0) -> 'str':
        """Serialise one-line record to a log line.

        Args:
            data (:obj:`~zlogging.model.Model`): Log record.
            lineno: Line number of current line.

        Returns:
            The converted log string.

        """

    def dump(self, data: 'Iterable[Model]', file: 'TextFile') -> 'int':
        """Write log file.

        Args:
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.
            file: Log file object opened in text mode.

        Returns:
            The file offset after writing.

        """
        return self.write_file(file, data)

    def dumps(self, data: 'Iterable[Model]') -> 'str':
        """Serialise records to a log line.

        Args:
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The converted log string.

        """
        return self.dump_file(data)


class JSONWriter(BaseWriter):
    """JSON log writer.

    Args:
        encoder: JSON encoder class.

    """
    #: JSON encoder class.
    encoder: 'Type[JSONEncoder]'

    @property
    def format(self) -> 'Literal["json"]':
        """Log file format."""
        return 'json'

    def __init__(self, encoder: 'Optional[Type[JSONEncoder]]' = None) -> 'None':
        if encoder is None:
            encoder = json.JSONEncoder
        self.encoder = encoder

    def write_file(self, file: 'TextFile', data: 'Iterable[Model]') -> 'int':
        """Write log file.

        Args:
            file: Log file object opened in text mode.
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The file offset after writing.

        """
        offset = -1
        for index, line in enumerate(data, start=1):
            offset = self.write_line(file, line, lineno=index)
        return offset

    def write_line(self, file: 'TextFile', data: 'Model',
                   lineno: 'Optional[int]' = 0) -> 'int':
        """Write log line as one-line record.

        Args:
            file: Log file object opened in text mode.
            data: Log record.
            lineno: Line number of current line.

        Returns:
            The file offset after writing.

        Raises:
            :exc:`JSONWriterError`: If failed to serialise ``data`` as JSON.

        """
        try:
            return file.write('%s\n' % json.dumps(data.tojson(), cls=self.encoder))  # pylint: disable=consider-using-f-string
        except TypeError as error:
            raise JSONWriterError(str(error), lineno=lineno) from error

    def dump_file(self, data: 'Optional[Iterable[Model]]' = None) -> 'str':
        """Serialise records to a log line.

        Args:
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The converted log string.

        """
        if data is None:
            return ''
        return ''.join(self.dump_line(line, lineno=index) for index, line in enumerate(data, start=1))

    def dump_line(self, data: 'Model', lineno: 'Optional[int]' = 0) -> 'str':
        """Serialise one-line record to a log line.

        Args:
            data: Log record.
            lineno: Line number of current line.

        Returns:
            The converted log string.

        Raises:
            :exc:`JSONWriterError`: If failed to serialise ``data`` as JSON.

        """
        try:
            return '%s\n' % json.dumps(data.tojson(), cls=self.encoder)  # pylint: disable=consider-using-f-string
        except TypeError as error:
            raise JSONWriterError(str(error), lineno=lineno) from error


class ASCIIWriter(BaseWriter):
    """ASCII log writer.

    Args:
        separator: Field separator when writing log lines.
        empty_field: Placeholder for empty field.
        unset_field: Placeholder for unset field.
        set_separator: Separator for ``set``/``vector`` fields.

    """
    #: Field separator when writing log lines.
    separator: 'bytes'
    str_separator: 'str'
    #: Placeholder for empty field.
    empty_field: 'bytes'
    str_empty_field: 'str'
    #: Placeholder for unset field.
    unset_field: 'bytes'
    str_unset_field: 'str'
    #: Separator for ``set``/``vector`` fields.
    set_separator: 'bytes'
    str_set_separator: 'str'

    @property
    def format(self) -> str:
        """Log file format."""
        return 'ascii'

    def __init__(self, separator: 'Optional[AnyStr]' = None, empty_field: 'Optional[AnyStr]' = None,
                 unset_field: 'Optional[AnyStr]' = None, set_separator: 'Optional[AnyStr]' = None) -> 'None':
        if separator is None:
            self.separator = b'\x09'
            self.str_separator = '\x09'
        elif isinstance(separator, bytes):
            self.separator = separator
            self.str_separator = separator.decode('ascii')
        else:
            self.separator = separator.encode('ascii')
            self.str_separator = separator

        if empty_field is None:
            self.empty_field = b'(empty)'
            self.str_empty_field = '(empty)'
        elif isinstance(empty_field, str):
            self.empty_field = empty_field.encode('ascii')
            self.str_empty_field = empty_field
        else:
            self.empty_field = empty_field
            self.str_empty_field = empty_field.decode('ascii')

        if unset_field is None:
            self.unset_field = b'-'
            self.str_unset_field = '-'
        elif isinstance(unset_field, str):
            self.unset_field = unset_field.encode('ascii')
            self.str_unset_field = unset_field
        else:
            self.unset_field = unset_field
            self.str_unset_field = unset_field.decode('ascii')

        if set_separator is None:
            self.set_separator = b','
            self.str_set_separator = ','
        elif isinstance(set_separator, str):
            self.set_separator = set_separator.encode('ascii')
            self.str_set_separator = set_separator
        else:
            self.set_separator = set_separator
            self.str_set_separator = set_separator.decode('ascii')

    def write_file(self, file: 'TextFile', data: 'Iterable[Model]') -> 'int':
        """Write log file.

        Args:
            file: Log file object opened in text mode.
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.

        Returns:
            The file offset after writing.

        """
        if data:
            line = next(data)  # type: ignore[call-overload]
            self.write_head(file, line)
            self.write_line(file, line, lineno=1)
            lineno_start = 2
        else:
            self.write_head(file)
            lineno_start = 1

        for index, line in enumerate(data, start=lineno_start):
            self.write_line(file, line, lineno=index)
        return self.write_tail(file)

    def write_line(self, file: 'TextFile', data: 'Model',
                   lineno: 'Optional[int]' = 0) -> 'int':
        """Write log line as one-line record.

        Args:
            file: Log file object opened in text mode.
            data: Log record.
            lineno: Line number of current line.

        Returns:
            The file offset after writing.

        Raises:
            :exc:`ASCIIWriterError`: If failed to serialise ``data`` as ASCII.

        """
        try:
            return file.write('%s\n' % self.str_separator.join(data.toascii().values()))  # pylint: disable=consider-using-f-string
        except TypeError as error:
            raise ASCIIWriterError(str(error), lineno=lineno) from error

    def write_head(self, file: 'TextFile', data: 'Optional[Model]' = None) -> 'int':
        """Write header fields of ASCII log file.

        Args:
            file: Log file object opened in text mode.
            data: Log record.

        Returns:
            The file offset after writing.

        """
        separator = self.str_separator
        if data is None:
            empty_field = self.str_empty_field
            unset_field = self.str_unset_field
            set_separator = self.str_set_separator

            fields = ''
            types = ''
        else:
            empty_field = data.empty_field.decode('ascii')
            unset_field = data.unset_field.decode('ascii')
            set_separator = data.set_separator.decode('ascii')

            line_fields = data.fields
            fields = separator.join(line_fields.keys())
            types = separator.join(field.zeek_type for field in line_fields.values())

        file.write('#separator %s\n' % unicode_escape(self.separator))  # pylint: disable=consider-using-f-string
        file.write('#set_separator%s%s\n' % (separator, set_separator))  # pylint: disable=consider-using-f-string
        file.write('#empty_field%s%s\n' % (separator, empty_field))  # pylint: disable=consider-using-f-string
        file.write('#unset_field%s%s\n' % (separator, unset_field))  # pylint: disable=consider-using-f-string
        file.write('#path%s%s\n' % (separator, os.path.splitext(file.name)[0]))  # pylint: disable=consider-using-f-string
        file.write('#open%s%s\n' % (separator, time.strftime(r'%Y-%m-%d-%H-%M-%S')))  # pylint: disable=consider-using-f-string
        file.write('#fields%s%s\n' % (separator, fields))  # pylint: disable=consider-using-f-string
        return file.write('#types%s%s\n' % (separator, types))  # pylint: disable=consider-using-f-string

    def write_tail(self, file: 'TextFile') -> 'int':
        """Write trailing fields of ASCII log file.

        Args:
            file: Log file object opened in text mode.

        Returns:
            The file offset after writing.

        """
        return file.write('#close%s%s\n' % (self.str_separator, time.strftime(r'%Y-%m-%d-%H-%M-%S')))  # pylint: disable=consider-using-f-string

    def dump_file(self, data: 'Optional[Iterable[Model]]' = None, name: 'Optional[str]' = None) -> 'str':  # pylint: disable=arguments-differ
        """Serialise records to a log line.

        Args:
            data: Log records as an :class:`~typing.Iterable` of
                :class:`~zlogging.model.Model` per line.
            name: Log file name.

        Returns:
            The converted log string.

        """
        if data:
            data_iter = iter(data)
            line = next(data_iter)

            buffer = self.dump_head(line, name=name)
            buffer += self.dump_line(line, lineno=1)

            buffer += ''.join(self.dump_line(line, lineno=index)
                              for index, line in enumerate(data_iter, start=2))
        else:
            buffer = self.dump_head(name=name)

        buffer += self.dump_tail()
        return buffer

    def dump_line(self, data: Model, lineno: 'Optional[int]' = 0) -> 'str':
        """Serialise one-line record to a log line.

        Args:
            data: Log record.
            lineno: Line number of current line.

        Returns:
            The converted log string.

        Raises:
            :exc:`ASCIIWriterError`: If failed to serialise ``data`` as ASCII.

        """
        try:
            return '%s\n' % self.str_separator.join(data.toascii().values())  # pylint: disable=consider-using-f-string
        except TypeError as error:
            raise ASCIIWriterError(str(error), lineno=lineno) from error

    def dump_head(self, data: 'Optional[Model]' = None, name: 'Optional[str]' = None) -> 'str':
        """Serialise header fields of ASCII log file.

        Args:
            data: Log record.
            name: Log file name.

        Returns:
            The converted log string.

        """
        if name is None:
            name = '<unknown>'

        separator = self.str_separator
        if data is None:
            empty_field = self.str_empty_field
            unset_field = self.str_unset_field
            set_separator = self.str_set_separator

            fields = ''
            types = ''
        else:
            empty_field = data.empty_field.decode('ascii')
            unset_field = data.unset_field.decode('ascii')
            set_separator = data.set_separator.decode('ascii')

            line_fields = data.fields
            fields = separator.join(line_fields.keys())
            types = separator.join(field.zeek_type for field in line_fields.values())

        buffer = '#separator %s\n' % unicode_escape(self.separator)  # pylint: disable=consider-using-f-string
        buffer += '#set_separator%s%s\n' % (separator, set_separator)  # pylint: disable=consider-using-f-string
        buffer += '#empty_field%s%s\n' % (separator, empty_field)  # pylint: disable=consider-using-f-string
        buffer += '#unset_field%s%s\n' % (separator, unset_field)  # pylint: disable=consider-using-f-string
        buffer += '#path%s%s\n' % (separator, os.path.splitext(name)[0])  # pylint: disable=consider-using-f-string
        buffer += '#open%s%s\n' % (separator, time.strftime(r'%Y-%m-%d-%H-%M-%S'))  # pylint: disable=consider-using-f-string
        buffer += '#fields%s%s\n' % (separator, fields)  # pylint: disable=consider-using-f-string
        buffer += '#types%s%s\n' % (separator, types)  # pylint: disable=consider-using-f-string
        return buffer

    def dump_tail(self) -> 'str':
        """Serialise trailing fields of ASCII log file.

        Returns:
            The converted log string.

        """
        return '#close%s%s\n' % (self.str_separator, time.strftime(r'%Y-%m-%d-%H-%M-%S'))  # pylint: disable=consider-using-f-string


def write_json(data: 'Iterable[Model]', filename: 'PathLike[str]', writer: 'Optional[Type[JSONWriter]]' = None,  # pylint: disable=unused-argument,keyword-arg-before-vararg
               encoder: 'Optional[Type[JSONEncoder]]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
    """Write JSON log file.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        filename: Log file name.
        writer: Writer class.
        encoder: JSON encoder class.
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """
    if writer is None:
        writer = JSONWriter
    json_writer = writer(encoder=encoder)
    json_writer.write(filename, data)


def dump_json(data: 'Iterable[Model]', file: 'TextFile', writer: 'Optional[Type[JSONWriter]]' = None,  # pylint: disable=unused-argument,keyword-arg-before-vararg
              encoder: 'Optional[Type[JSONEncoder]]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
    """Write JSON log file.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        file: Log file object opened in text mode.
        writer: Writer class.
        encoder: JSON encoder class.
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """
    if writer is None:
        writer = JSONWriter
    json_writer = writer(encoder=encoder)
    json_writer.write_file(file, data)


def dumps_json(data: 'Optional[Iterable[Model]]' = None, writer: 'Optional[Type[JSONWriter]]' = None,  # pylint: disable=unused-argument,keyword-arg-before-vararg
               encoder: 'Optional[Type[JSONEncoder]]' = None, *args: 'Any', **kwargs: 'Any') -> 'str':
    """Write JSON log string.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        writer: Writer class.
        encoder: JSON encoder class.
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The JSON log string.

    """
    if writer is None:
        writer = JSONWriter
    json_writer = writer(encoder=encoder)
    return json_writer.dump_file(data)


def write_ascii(data: 'Iterable[Model]', filename: 'PathLike[str]',  # pylint: disable=unused-argument,keyword-arg-before-vararg
                writer: 'Optional[Type[ASCIIWriter]]' = None, separator: 'Optional[AnyStr]' = None,
                empty_field: 'Optional[AnyStr]' = None, unset_field: 'Optional[AnyStr]' = None,
                set_separator: 'Optional[AnyStr]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
    """Write ASCII log file.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        filename: Log file name.
        writer: Writer class.
        separator: Field separator when writing log lines.
        empty_field: Placeholder for empty field.
        unset_field: Placeholder for unset field.
        set_separator: Separator for ``set``/``vector`` fields.
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """
    if writer is None:
        writer = ASCIIWriter
    ascii_writer = writer(separator=separator, empty_field=empty_field,
                          unset_field=unset_field, set_separator=set_separator)
    ascii_writer.write(filename, data)


def dump_ascii(data: 'Iterable[Model]', file: 'TextFile',  # pylint: disable=unused-argument,keyword-arg-before-vararg
               writer: 'Optional[Type[ASCIIWriter]]' = None, separator: 'Optional[AnyStr]' = None,
               empty_field: 'Optional[AnyStr]' = None, unset_field: 'Optional[AnyStr]' = None,
               set_separator: 'Optional[AnyStr]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
    """Write ASCII log file.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        file: Log file object opened in text mode.
        writer: Writer class.
        separator: Field separator when writing log lines.
        empty_field: Placeholder for empty field.
        unset_field: Placeholder for unset field.
        set_separator: Separator for ``set``/``vector`` fields.
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """
    if writer is None:
        writer = ASCIIWriter
    ascii_writer = writer(separator=separator, empty_field=empty_field,
                          unset_field=unset_field, set_separator=set_separator)
    ascii_writer.write_file(file, data)


def dumps_ascii(data: 'Optional[Iterable[Model]]' = None,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                writer: 'Optional[Type[ASCIIWriter]]' = None, separator: 'Optional[AnyStr]' = None,
                empty_field: 'Optional[AnyStr]' = None, unset_field: 'Optional[AnyStr]' = None,
                set_separator: 'Optional[AnyStr]' = None, *args: 'Any', **kwargs: 'Any') -> 'str':
    """Write ASCII log string.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        writer: Writer class.
        separator: Field separator when writing log lines.
        empty_field: Placeholder for empty field.
        unset_field: Placeholder for unset field.
        set_separator: Separator for ``set``/``vector`` fields.
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    Returns:
        The JSON log string.

    """
    if writer is None:
        writer = ASCIIWriter
    ascii_writer = writer(separator=separator, empty_field=empty_field,
                          unset_field=unset_field, set_separator=set_separator)
    return ascii_writer.dump_file(data)


def write(data: 'Iterable[Model]', filename: 'PathLike[str]',
          format: 'str', *args: 'Any', **kwargs: 'Any') -> 'None':  # pylint: disable=keyword-arg-before-vararg,redefined-builtin
    """Write Bro/Zeek log file.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        filename: Log file name.
        format: Log format.
        *args: See :func:`~zlogging.dumper.write_json` and
            :func:`~zlogging.dumper.write_ascii` for more information.
        **kwargs: See :func:`~zlogging.dumper.write_json` and
            :func:`~zlogging.dumper.write_ascii` for more information.

    Raises:
        :exc:`WriterFormatError`: If ``format`` is not supported.

    """
    if format == 'ascii':
        return write_ascii(data, filename, *args, **kwargs)
    if format == 'json':
        return write_json(data, filename, *args, **kwargs)
    raise WriterFormatError('unsupported format: %s' % format)  # pylint: disable=consider-using-f-string


def dump(data: 'Iterable[Model]', file: 'TextFile',
         format: 'str', *args: 'Any', **kwargs: 'Any') -> 'None':  # pylint: disable=keyword-arg-before-vararg,redefined-builtin
    """Write Bro/Zeek log file.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        format: Log format.
        file: Log file object opened in text mode.
        *args: See :func:`~zlogging.dumper.dump_json` and
            :func:`~zlogging.dumper.dump_ascii` for more information.
        **kwargs: See :func:`~zlogging.dumper.dump_json` and
            :func:`~zlogging.dumper.dump_ascii` for more information.

    Raises:
        :exc:`WriterFormatError`: If ``format`` is not supported.

    """
    if format == 'ascii':
        return dump_ascii(data, file, *args, **kwargs)
    if format == 'json':
        return dump_json(data, file, *args, **kwargs)
    raise WriterFormatError('unsupported format: %s' % format)  # pylint: disable=consider-using-f-string


def dumps(data: 'Iterable[Model]', format: 'str', *args: 'Any', **kwargs: 'Any') -> 'str':  # pylint: disable=keyword-arg-before-vararg,redefined-builtin
    """Write Bro/Zeek log string.

    Args:
        data: Log records as an :class:`~typing.Iterable` of
            :class:`~zlogging.model.Model` per line.
        format: Log format.
        *args: See :func:`~zlogging.dumper.dumps_json` and
            :func:`~zlogging.dumper.dumps_ascii` for more information.
        **kwargs: See :func:`~zlogging.dumper.dumps_json` and
            :func:`~zlogging.dumper.dumps_ascii` for more information.

    Raises:
        :exc:`WriterFormatError`: If ``format`` is not supported.

    """
    if format == 'ascii':
        return dumps_ascii(data, *args, **kwargs)
    if format == 'json':
        return dumps_json(data, *args, **kwargs)
    raise WriterFormatError('unsupported format: %s' % format)  # pylint: disable=consider-using-f-string
