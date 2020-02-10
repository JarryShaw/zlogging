# -*- coding: utf-8 -*-
"""Namespace: SSL.

:module: zlogging.enum.SSL
"""

from zlogging._compat import enum


@enum.unique
class SctSource(enum.IntFlag):
    """List of the different sources for Signed Certificate Timestamp

    c.f. `policy/protocols/ssl/validate-sct.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/ssl/validate-sct.zeek.html>`__

    """

    _ignore_ = 'SctSource _'
    SctSource = vars()

    #: Signed Certificate Timestamp was encountered in the extension of
    #: an X.509 certificate.
    #: :currentmodule: zlogging.enum.SSL
    SctSource['SCT_X509_EXT'] = enum.auto()

    #: Signed Certificate Timestamp was encountered in an TLS session
    #: extension.
    #: :currentmodule: zlogging.enum.SSL
    SctSource['SCT_TLS_EXT'] = enum.auto()

    #: Signed Certificate Timestamp was encountered in the extension of
    #: an stapled OCSP reply.
    #: :currentmodule: zlogging.enum.SSL
    SctSource['SCT_OCSP_EXT'] = enum.auto()
