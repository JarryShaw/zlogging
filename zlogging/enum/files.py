# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Files``."""

from zlogging._compat import enum


@enum.unique
class Tag(enum.IntFlag):
    """Enum: ``Files::Tag``.

    See Also:
        `File Analyzers <https://docs.zeek.org/en/stable/scripts/File Analyzers.html#type-Files::Tag>`__

    """

    _ignore_ = 'Tag _'
    Tag = vars()

    ANALYZER_DATA_EVENT = enum.auto()

    ANALYZER_ENTROPY = enum.auto()

    ANALYZER_EXTRACT = enum.auto()

    ANALYZER_MD5 = enum.auto()

    ANALYZER_SHA1 = enum.auto()

    ANALYZER_SHA224 = enum.auto()

    ANALYZER_SHA256 = enum.auto()

    ANALYZER_SHA384 = enum.auto()

    ANALYZER_SHA512 = enum.auto()

    ANALYZER_PE = enum.auto()

    ANALYZER_OCSP_REPLY = enum.auto()

    ANALYZER_OCSP_REQUEST = enum.auto()

    ANALYZER_X509 = enum.auto()
