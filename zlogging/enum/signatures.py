# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Signatures``."""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """Enum: ``Signatures::Action``.

    These are the default actions you can apply to signature matches. All of them write the signature
    record to the logging stream unless declared otherwise.

    See Also:
        `base/frameworks/signatures/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/signatures/main.zeek.html#type-Signatures::Action>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: Ignore this signature completely (even for scan detection).
    #: Don’t write to the signatures logging stream.
    SIG_IGNORE = enum.auto()

    #: Process through the various aggregate techniques, but don’t
    #: report individually and don’t write to the signatures logging
    #: stream.
    SIG_QUIET = enum.auto()

    #: Generate a notice.
    SIG_LOG = enum.auto()

    #: The same as Signatures::SIG\_LOG, but ignore for
    #: aggregate/scan processing.
    SIG_FILE_BUT_NO_SCAN = enum.auto()

    #: Generate a notice and set it to be alarmed upon.
    SIG_ALARM = enum.auto()

    #: Alarm once per originator.
    SIG_ALARM_PER_ORIG = enum.auto()

    #: Alarm once and then never again.
    SIG_ALARM_ONCE = enum.auto()

    #: Count signatures per responder host and alarm with the
    #: Signatures::Count\_Signature notice if a threshold
    #: defined by Signatures::count\_thresholds is reached.
    SIG_COUNT_PER_RESP = enum.auto()

    #: Don’t alarm, but generate per-orig summary.
    SIG_SUMMARY = enum.auto()
