# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
"""Namespace: ``Input``."""

from zlogging._compat import enum


@enum.unique
class Event(enum.IntFlag):
    """Enum: ``Input::Event``.

    Type that describes what kind of change occurred.

    See Also:
        `base/frameworks/input/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/input/main.zeek.html#type-Input::Event>`__

    """

    _ignore_ = 'Event _'
    Event = vars()

    #: New data has been imported.
    Event['EVENT_NEW'] = enum.auto()

    #: Existing data has been changed.
    Event['EVENT_CHANGED'] = enum.auto()

    #: Previously existing data has been removed.
    Event['EVENT_REMOVED'] = enum.auto()


@enum.unique
class Mode(enum.IntFlag):
    """Enum: ``Input::Mode``.

    Type that defines the input stream read mode.

    See Also:
        `base/frameworks/input/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/input/main.zeek.html#type-Input::Mode>`__

    """

    _ignore_ = 'Mode _'
    Mode = vars()

    #: Do not automatically reread the file after it has been read.
    Mode['MANUAL'] = enum.auto()

    #: Reread the entire file each time a change is found.
    Mode['REREAD'] = enum.auto()

    #: Read data from end of file each time new data is appended.
    Mode['STREAM'] = enum.auto()


@enum.unique
class Reader(enum.IntFlag):
    """Enum: ``Input::Reader``.

    See Also:
        `base/frameworks/input/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/input/main.zeek.html#type-Input::Reader>`__

    """

    _ignore_ = 'Reader _'
    Reader = vars()

    Reader['READER_ASCII'] = enum.auto()

    Reader['READER_BENCHMARK'] = enum.auto()

    Reader['READER_BINARY'] = enum.auto()

    Reader['READER_CONFIG'] = enum.auto()

    Reader['READER_RAW'] = enum.auto()

    Reader['READER_SQLITE'] = enum.auto()
