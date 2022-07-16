# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``SSL``."""

from zlogging._compat import enum


@enum.unique
class SctSource(enum.IntFlag):
    """Enum: ``SSL::SctSource``.

    List of the different sources for Signed Certificate Timestamp.

    See Also:
        `policy/protocols/ssl/validate-sct.zeek <https://docs.zeek.org/en/stable/scripts/policy/protocols/ssl/validate-sct.zeek.html#type-SSL::SctSource>`__

    """

    _ignore_ = 'SctSource _'
    SctSource = vars()

    #: Signed Certificate Timestamp was encountered in the extension of
    #: an X.509 certificate.
    SCT_X509_EXT = enum.auto()

    #: Signed Certificate Timestamp was encountered in an TLS session
    #: extension.
    SCT_TLS_EXT = enum.auto()

    #: Signed Certificate Timestamp was encountered in the extension of
    #: an stapled OCSP reply.
    SCT_OCSP_EXT = enum.auto()
