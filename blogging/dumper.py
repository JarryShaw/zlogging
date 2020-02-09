# -*- coding: utf-8 -*-
"""Bro/Zeek log dumper."""

import abc
import json
import os
import time

import blogging._typing as typing
from blogging._aux import unicode_escape
from blogging._exc import ASCIIWriterError, JSONWriterError, WriterFormatError
from blogging.model import Model

__all__ = [
    'write', 'write_ascii', 'write_json',
    'dumps', 'dumps_ascii', 'dumps_json',
    'dump', 'dump_ascii', 'dump_json',
    'ASCIIWriter', 'JSONWriter',
]


class BaseWriter(metaclass=abc.ABCMeta):
    """Basic log writer."""

    @property
    @abc.abstractmethod
    def format(self) -> str:
        """str: Log file format."""

    def write(self, filename: typing.PathLike, data: typing.Iterable[Model]) -> int:
        """Write log file.

        Args:
            filename: log file name
            data: log records as an :obj:`Iterable` per line

        Returns:
            The file offset after writing.

        """
        with open(filename, 'w') as file:
            offset = self.write_file(file, data)
        return offset

    @abc.abstractmethod
    def write_file(self, file: typing.TextFile, data: typing.Iterable[Model]) -> int:
        """Write log file.

        Args:
            file: log file object opened in text mode
            data: log records as an :obj:`Iterable` per line

        Returns:
            The file offset after writing.

        """

    @abc.abstractmethod
    def write_line(self, file: typing.TextFile, data: Model,
                   lineno: typing.Optional[int] = 0) -> int:
        """Write log line as one-line record.

        Args:
            file: log file object opened in text mode
            data: log record
            lineno: line number of current line

        Returns:
            The file offset after writing.

        """

    @abc.abstractmethod
    def dump_file(self, data: typing.Iterable[Model]) -> str:
        """Serialise records to a log line.

        Args:
            data: log records as an :obj:`Iterable` per line

        Returns:
            The converted log string.

        """

    @abc.abstractmethod
    def dump_line(self, data: Model, lineno: typing.Optional[int] = 0) -> str:
        """Serialise one-line record to a log line.

        Args:
            data: log record
            lineno: line number of current line

        Returns:
            The converted log string.

        """

    def dump(self, data: typing.Iterable[Model], file: typing.TextFile) -> int:
        """Write log file.

        Args:
            data: log records as an :obj:`Iterable` per line
            file: log file object opened in text mode

        Returns:
            The file offset after writing.

        """
        return self.write_file(file, data)

    def dumps(self, data: typing.Iterable[Model]) -> str:
        """Serialise records to a log line.

        Args:
            data: log records as an :obj:`Iterable` per line

        Returns:
            The converted log string.

        """
        return self.dump_file(data)


class JSONWriter(BaseWriter):
    """JSON log writer."""

    @property
    def format(self) -> str:
        """str: Log file format."""
        return 'json'

    def write_file(self, file: typing.TextFile, data: typing.Iterable[Model]) -> int:
        """Write log file.

        Args:
            file: log file object opened in text mode
            data: log records as an :obj:`Iterable` per line

        Returns:
            The file offset after writing.

        """
        for index, line in enumerate(data, start=1):
            offset = self.write_line(file, line, lineno=index)
        return offset

    def write_line(self, file: typing.TextFile, data: Model,
                   lineno: typing.Optional[int] = 0) -> int:
        """Write log line as one-line record.

        Args:
            file: log file object opened in text mode
            data: log record
            lineno: line number of current line

        Returns:
            The file offset after writing.

        """
        try:
            return file.write('%s\n' % json.dumps(data.tojson()))
        except TypeError as error:
            raise JSONWriterError(str(error), lineno=lineno)

    def dump_file(self, data: typing.Iterable[Model]) -> str:
        """Serialise records to a log line.

        Args:
            data: log records as an :obj:`Iterable` per line

        Returns:
            The converted log string.

        """
        return ''.join(self.dump_line(line, lineno=index) for index, line in enumerate(data, start=1))

    def dump_line(self, data: Model, lineno: typing.Optional[int] = 0) -> str:
        """Serialise one-line record to a log line.

        Args:
            data: log record
            lineno: line number of current line

        Returns:
            The converted log string.

        """
        try:
            return '%s\n' % json.dumps(data.tojson())
        except TypeError as error:
            raise JSONWriterError(str(error), lineno=lineno)


class ASCIIWriter(BaseWriter):
    """ASCII log writer.

    Attributes:
        separator (bytes): field separator when writing log lines
        empty_field (bytes): placeholder for empty field
        unset_field (bytes): placeholder for unset field
        set_separator (bytes): separator for set/list fields

    """

    @property
    def format(self) -> str:
        """str: Log file format."""
        return 'ascii'

    def __init__(self,
                 separator: typing.Optional[typing.AnyStr] = None,
                 empty_field: typing.Optional[typing.AnyStr] = None,
                 unset_field: typing.Optional[typing.AnyStr] = None,
                 set_separator: typing.Optional[typing.AnyStr] = None):
        """Initialisation.

        Args:
            separator (:obj:`str` or :obj:`bytes`, optional): field separator when writing log lines
            empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
            unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
            set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields

        """
        if separator is None:
            separator = b'\x09'
        if empty_field is None:
            empty_field = b'(empty)'
        if unset_field is None:
            unset_field = b'-'
        if set_separator is None:
            set_separator = b','

        if isinstance(separator, bytes):
            self.separator = separator
            self.str_separator = separator.decode('ascii')
        else:
            self.separator = separator.encode('ascii')
            self.str_separator = separator

        if isinstance(empty_field, str):
            self.empty_field = empty_field.encode('ascii')
            self.str_empty_field = empty_field
        else:
            self.empty_field = empty_field
            self.str_empty_field = empty_field.decode('ascii')

        if isinstance(unset_field, str):
            self.unset_field = unset_field.encode('ascii')
            self.str_unset_field = unset_field
        else:
            self.unset_field = unset_field
            self.str_unset_field = unset_field.decode('ascii')

        if isinstance(set_separator, str):
            self.set_separator = set_separator.encode('ascii')
            self.str_set_separator = set_separator
        else:
            self.set_separator = set_separator
            self.str_set_separator = set_separator.decode('ascii')

    def write_file(self, file: typing.TextFile, data: typing.Iterable[Model]) -> int:
        """Write log file.

        Args:
            file: log file object opened in text mode
            data: log records as an :obj:`Iterable` per line

        Returns:
            The file offset after writing.

        """
        if data:
            line = next(data)
            self.write_head(file, line)
            self.write_line(file, line, lineno=1)
            lineno_start = 2
        else:
            self.write_head(file)
            lineno_start = 1

        for index, line in enumerate(data, start=lineno_start):
            self.write_line(file, line, lineno=index)
        return self.write_tail(file)

    def write_line(self, file: typing.TextFile, data: Model,
                   lineno: typing.Optional[int] = 0) -> int:
        """Write log line as one-line record.

        Args:
            file: log file object opened in text mode
            data: log record
            lineno: line number of current line

        Returns:
            The file offset after writing.

        """
        return file.write('%s\n' % self.separator.join(data.toascii().values()))

    def write_head(self, file: typing.TextFile, data: typing.Optional[Model] = None) -> int:
        """Write header fields of ASCII log file.

        Args:
            file: log file object opened in text mode
            data: log record

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
            types = separator.join(line_fields.values())

        file.write('#separator %s\n' % unicode_escape(self.separator))
        file.write('#set_separator%s%s\n' % (separator, set_separator))
        file.write('#empty_field%s%s\n' % (separator, empty_field))
        file.write('#unset_field%s%s\n' % (separator, unset_field))
        file.write('#path%s%s\n' % (separator, os.path.splitext(file.name)[0]))
        file.write('#open%s%s\n' % (separator, time.strftime(r'%Y-%m-%d-%H-%M-%S')))
        file.write('#fields%s%s\n' % (separator, fields))
        return file.write('#types%s%s\n' % (separator, types))

    def write_tail(self, file: typing.TextFile) -> int:
        """Write trailing fields of ASCII log file.

        Args:
            file: log file object opened in text mode

        Returns:
            The file offset after writing.

        """
        return file.write('#close%s%s\n' % (self.str_separator, time.strftime(r'%Y-%m-%d-%H-%M-%S')))

    def dump_file(self, data: typing.Iterable[Model], name: typing.Optional[str] = None) -> str:  # pylint: disable=arguments-differ
        """Serialise records to a log line.

        Args:
            data: log records as an :obj:`Iterable` per line
            name: log file name

        Returns:
            The converted log string.

        """
        if data:
            line = next(data)
            buffer = self.dump_head(data, name=name)
            buffer += self.dump_line(line, lineno=1)
            lineno_start = 2
        else:
            buffer = self.dump_head(name=name)
            lineno_start = 1

        buffer += ''.join(self.dump_line(line, lineno=index) for index, line in enumerate(data, start=lineno_start))
        buffer += self.dump_tail()

    def dump_line(self, data: Model, lineno: typing.Optional[int] = 0) -> str:
        """Serialise one-line record to a log line.

        Args:
            data: log record
            lineno: line number of current line

        Returns:
            The converted log string.

        """
        try:
            return self.str_separator.join(data.toascii().values())
        except TypeError as error:
            raise ASCIIWriterError(str(error), lineno=lineno)

    def dump_head(self, data: typing.Optional[Model] = None, name: typing.Optional[str] = None) -> str:
        """Serialise header fields of ASCII log file.

        Args:
            data: log record
            name: log file name

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
            types = separator.join(line_fields.values())

        buffer = '#separator %s\n' % unicode_escape(self.separator)
        buffer += '#set_separator%s%s\n' % (separator, set_separator)
        buffer += '#empty_field%s%s\n' % (separator, empty_field)
        buffer += '#unset_field%s%s\n' % (separator, unset_field)
        buffer += '#path%s%s\n' % (separator, os.path.splitext(name)[0])
        buffer += '#open%s%s\n' % (separator, time.strftime(r'%Y-%m-%d-%H-%M-%S'))
        buffer += '#fields%s%s\n' % (separator, fields)
        buffer += '#types%s%s\n' % (separator, types)
        return buffer

    def dump_tail(self) -> str:
        """Serialise trailing fields of ASCII log file.

        Returns:
            The converted log string.

        """
        return '#close%s%s\n' % (self.str_separator, time.strftime(r'%Y-%m-%d-%H-%M-%S'))


def write_json(data: typing.Iterable[Model], filename: typing.PathLike,  # pylint: disable=unused-argument,keyword-arg-before-vararg
               writer: typing.Optional[typing.Type[JSONWriter]] = None,
               *args: typing.Args, **kwargs: typing.Kwargs):
    """Write JSON log file.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        filename: log file name
        writer (:obj:`JSONWriter`, optional): writer class

    """
    if writer is None:
        writer = JSONWriter
    json_writer = writer()
    json_writer.write(filename, data)


def dump_json(data: typing.Iterable[Model], file: typing.TextFile,  # pylint: disable=unused-argument,keyword-arg-before-vararg
              writer: typing.Optional[typing.Type[JSONWriter]] = None,
              *args: typing.Args, **kwargs: typing.Kwargs):
    """Write JSON log file.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        file: log file object opened in text mode
        writer (:obj:`JSONWriter`, optional): writer class

    """
    if writer is None:
        writer = JSONWriter
    json_writer = writer()
    json_writer.write_file(file, data)


def dumps_json(data: typing.Iterable[Model] = None,  # pylint: disable=unused-argument,keyword-arg-before-vararg
               writer: typing.Optional[typing.Type[JSONWriter]] = None,
               *args: typing.Args, **kwargs: typing.Kwargs) -> str:
    """Write JSON log string.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        writer (:obj:`JSONWriter`, optional): writer class

    Returns:
        The JSON log string.

    """
    if writer is None:
        writer = JSONWriter
    json_writer = writer()
    return json_writer.dump_file(data)


def write_ascii(data: typing.Iterable[Model], filename: typing.PathLike,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                writer: typing.Optional[typing.Type[ASCIIWriter]] = None,
                separator: typing.Optional[typing.AnyStr] = None,
                empty_field: typing.Optional[typing.AnyStr] = None,
                unset_field: typing.Optional[typing.AnyStr] = None,
                set_separator: typing.Optional[typing.AnyStr] = None,
                *args: typing.Args, **kwargs: typing.Kwargs):
    """Write ASCII log file.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        filename: log file name
        writer (:obj:`ASCIIWriter`, optional): writer class
        separator (:obj:`str` or :obj:`bytes`, optional): field separator when writing log lines
        empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
        set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields

    """
    if writer is None:
        writer = ASCIIWriter
    ascii_writer = writer(separator=separator, empty_field=empty_field,
                          unset_field=unset_field, set_separator=set_separator)
    ascii_writer.write(filename, data)


def dump_ascii(data: typing.Iterable[Model], file: typing.TextFile,  # pylint: disable=unused-argument,keyword-arg-before-vararg
               writer: typing.Optional[typing.Type[ASCIIWriter]] = None,
               separator: typing.Optional[typing.AnyStr] = None,
               empty_field: typing.Optional[typing.AnyStr] = None,
               unset_field: typing.Optional[typing.AnyStr] = None,
               set_separator: typing.Optional[typing.AnyStr] = None,
               *args: typing.Args, **kwargs: typing.Kwargs):
    """Write ASCII log file.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        file: log file object opened in text mode
        writer (:obj:`ASCIIWriter`, optional): writer class
        separator (:obj:`str` or :obj:`bytes`, optional): field separator when writing log lines
        empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
        set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields

    """
    if writer is None:
        writer = ASCIIWriter
    ascii_writer = writer(separator=separator, empty_field=empty_field,
                          unset_field=unset_field, set_separator=set_separator)
    ascii_writer.write_file(file, data)


def dumps_ascii(data: typing.Iterable[Model] = None,  # pylint: disable=unused-argument,keyword-arg-before-vararg
                writer: typing.Optional[typing.Type[ASCIIWriter]] = None,
                separator: typing.Optional[typing.AnyStr] = None,
                empty_field: typing.Optional[typing.AnyStr] = None,
                unset_field: typing.Optional[typing.AnyStr] = None,
                set_separator: typing.Optional[typing.AnyStr] = None,
                *args: typing.Args, **kwargs: typing.Kwargs) -> str:
    """Write ASCII log string.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        writer (:obj:`ASCIIWriter`, optional): writer class
        separator (:obj:`str` or :obj:`bytes`, optional): field separator when writing log lines
        empty_field (:obj:`bytes` or :obj:`str`, optional): placeholder for empty field
        unset_field (:obj:`bytes` or :obj:`str`, optional): placeholder for unset field
        set_separator (:obj:`bytes` or :obj:`str`, optional): separator for set/vector fields

    Returns:
        The JSON log string.

    """
    if writer is None:
        writer = ASCIIWriter
    ascii_writer = writer(separator=separator, empty_field=empty_field,
                          unset_field=unset_field, set_separator=set_separator)
    return ascii_writer.dump_file(data)


def write(data: typing.Iterable[Model], filename: typing.PathLike,  # pylint: disable=unused-argument,keyword-arg-before-vararg
          format: str, *args: typing.Args, **kwargs: typing.Kwargs):  # pylint: disable=redefined-builtin
    """Write Bro/Zeek log file.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        filename: log file name
        format: log format
        *args: see :func:`write_json` and :func:`write_ascii` for more information
        **kwargs: see :func:`write_json` and :func:`write_ascii` for more information

    """
    if format == 'ascii':
        return write_ascii(data, filename, *args, **kwargs)
    if format == 'json':
        return write_json(data, filename, *args, **kwargs)
    raise WriterFormatError('unsupported format: %s' % format)


def dump(data: typing.Iterable[Model], file: typing.TextFile,  # pylint: disable=unused-argument,keyword-arg-before-vararg
         format: str, *args: typing.Args, **kwargs: typing.Kwargs):  # pylint: disable=redefined-builtin
    """Write Bro/Zeek log file.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        format: log format
        file: log file object opened in text mode
        *args: see :func:`write_json` and :func:`write_ascii` for more information
        **kwargs: see :func:`write_json` and :func:`write_ascii` for more information

    """
    if format == 'ascii':
        return dump_ascii(data, file, *args, **kwargs)
    if format == 'json':
        return dump_json(data, file, *args, **kwargs)
    raise WriterFormatError('unsupported format: %s' % format)


def dumps(data: typing.Iterable[Model], format: str,  # pylint: disable=unused-argument,keyword-arg-before-vararg,redefined-builtin
          *args: typing.Args, **kwargs: typing.Kwargs):
    """Write Bro/Zeek log string.

    Args:
        data (:obj:`Iterable[Model]`): log records as an :obj:`Iterable` per line
        format: log format
        *args: see :func:`write_json` and :func:`write_ascii` for more information
        **kwargs: see :func:`write_json` and :func:`write_ascii` for more information

    """
    if format == 'ascii':
        return dumps_ascii(data, *args, **kwargs)
    if format == 'json':
        return dumps_json(data, *args, **kwargs)
    raise WriterFormatError('unsupported format: %s' % format)
