# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
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
    EVENT_NEW = enum.auto()

    #: Existing data has been changed.
    EVENT_CHANGED = enum.auto()

    #: Previously existing data has been removed.
    EVENT_REMOVED = enum.auto()


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
    MANUAL = enum.auto()

    #: Reread the entire file each time a change is found.
    REREAD = enum.auto()

    #: Read data from end of file each time new data is appended.
    STREAM = enum.auto()


@enum.unique
class Reader(enum.IntFlag):
    """Enum: ``Input::Reader``.

    See Also:
        `base/frameworks/input/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/input/main.zeek.html#type-Input::Reader>`__

    """

    _ignore_ = 'Reader _'
    Reader = vars()

    READER_ASCII = enum.auto()

    READER_BENCHMARK = enum.auto()

    READER_BINARY = enum.auto()

    READER_CONFIG = enum.auto()

    READER_RAW = enum.auto()

    READER_SQLITE = enum.auto()
