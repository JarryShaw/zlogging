# -*- coding: utf-8 -*-
"""Namespace: HTTP.

:module: zlogging.enum.HTTP
"""

from zlogging._compat import enum


@enum.unique
class Tags(enum.IntFlag):
    """Indicate a type of attack or compromise in the record to be logged.

    c.f. `base/protocols/http/main.zeek <https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html>`__

    """

    _ignore_ = 'Tags _'
    Tags = vars()

    #: Placeholder.
    #: :currentmodule: zlogging.enum.HTTP
    Tags['EMPTY'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of a URI based SQL injection attack.
    #: :currentmodule: zlogging.enum.HTTP
    Tags['URI_SQLI'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of client body based SQL injection attack.  This is
    #: typically the body content of a POST request. Not implemented
    #: yet.
    #: :currentmodule: zlogging.enum.HTTP
    Tags['POST_SQLI'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicator of a cookie based SQL injection attack. Not
    #: implemented yet.
    #: :currentmodule: zlogging.enum.HTTP
    Tags['COOKIE_SQLI'] = enum.auto()
