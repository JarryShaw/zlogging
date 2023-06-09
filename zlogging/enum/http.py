# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``HTTP``."""

from zlogging._compat import enum


@enum.unique
class Tags(enum.IntFlag):
    """Enum: ``HTTP::Tags``.

    Indicate a type of attack or compromise in the record to be logged.

    See Also:
        `base/protocols/http/main.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html#type-HTTP::Tags>`__

    """

    _ignore_ = 'Tags _'
    Tags = vars()

    #: Placeholder.
    EMPTY = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of a URI based SQL injection attack.
    URI_SQLI = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of client body based SQL injection attack.  This is
    #: typically the body content of a POST request. Not implemented
    #: yet.
    POST_SQLI = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of a cookie based SQL injection attack. Not
    #: implemented yet.
    COOKIE_SQLI = enum.auto()
