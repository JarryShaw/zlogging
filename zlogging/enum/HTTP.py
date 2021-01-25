# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error
"""Namespace: ``HTTP``."""

from zlogging._compat import enum


@enum.unique
class Tags(enum.IntFlag):
    """Enum: ``HTTP::Tags``.

    Indicate a type of attack or compromise in the record to be logged.

    See Also:
        `base/protocols/http/main.zeek`_

    .. _base/protocols/http/main.zeek: https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html#type-HTTP::Tags

    """

    _ignore_ = 'Tags _'
    Tags = vars()

    #: Placeholder.
    Tags['EMPTY'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of a URI based SQL injection attack.
    Tags['URI_SQLI'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of client body based SQL injection attack.  This is
    #: typically the body content of a POST request. Not implemented
    #: yet.
    Tags['POST_SQLI'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of a cookie based SQL injection attack. Not
    #: implemented yet.
    Tags['COOKIE_SQLI'] = enum.auto()
