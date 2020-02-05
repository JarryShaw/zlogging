# -*- coding: utf-8 -*-
"""Namespace: SSL."""

import enum


@enum.unique
class SctSource(enum.IntFlag):
    """List of the different sources for Signed Certificate Timestamp

    
    c.f. {html_path}
    """

    _ignore_ = 'SctSource _'
    SctSource = vars()

    # Signed Certificate Timestamp was encountered in the extension of
    # an X.509 certificate.
    SctSource['SCT_X509_EXT'] = enum.auto()

    # Signed Certificate Timestamp was encountered in an TLS session
    # extension.
    SctSource['SCT_TLS_EXT'] = enum.auto()

    # Signed Certificate Timestamp was encountered in the extension of
    # an stapled OCSP reply.
    SctSource['SCT_OCSP_EXT'] = enum.auto()
