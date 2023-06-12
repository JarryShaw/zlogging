# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Intel``."""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """Enum: ``Intel::Type``.

    Enum type to represent various types of intelligence data.

    See Also:
        `base/frameworks/intel/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: An IP address.
    ADDR = enum.auto()

    #: A subnet in CIDR notation.
    SUBNET = enum.auto()

    #: A complete URL without the prefix "http://".
    URL = enum.auto()

    #: Software name.
    SOFTWARE = enum.auto()

    #: Email address.
    EMAIL = enum.auto()

    #: DNS domain name.
    DOMAIN = enum.auto()

    #: A user name.
    USER_NAME = enum.auto()

    #: Certificate SHA-1 hash.
    CERT_HASH = enum.auto()

    #: Public key MD5 hash, formatted as hexadecimal digits delimited by colons.
    #: (SSH server host keys are a good example.)
    PUBKEY_HASH = enum.auto()

    #: (present if base/frameworks/intel/files.zeek is loaded)
    #: File hash which is non-hash type specific.  It’s up to the
    #: user to query for any relevant hash types.
    FILE_HASH = enum.auto()

    #: (present if base/frameworks/intel/files.zeek is loaded)
    #: File name.  Typically with protocols with definite
    #: indications of a file name.
    FILE_NAME = enum.auto()


@enum.unique
class Where(enum.IntFlag):
    """Enum: ``Intel::Where``.

    Enum to represent where data came from when it was discovered. The convention is to prefix the name
    with ``IN_``.

    See Also:
        `base/frameworks/intel/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Where>`__

    """

    _ignore_ = 'Where _'
    Where = vars()

    #: A catchall value to represent data of unknown provenance.
    IN_ANYWHERE = enum.auto()

    #: Conn::IN_ORIG
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Conn_IN_ORIG = enum.auto()

    #: Conn::IN_RESP
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Conn_IN_RESP = enum.auto()

    #: Files::IN_HASH
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Files_IN_HASH = enum.auto()

    #: Files::IN_NAME
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Files_IN_NAME = enum.auto()

    #: DNS::IN_REQUEST
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    DNS_IN_REQUEST = enum.auto()

    #: DNS::IN_RESPONSE
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    DNS_IN_RESPONSE = enum.auto()

    #: HTTP::IN_HOST_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    HTTP_IN_HOST_HEADER = enum.auto()

    #: HTTP::IN_REFERRER_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    HTTP_IN_REFERRER_HEADER = enum.auto()

    #: HTTP::IN_USER_AGENT_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    HTTP_IN_USER_AGENT_HEADER = enum.auto()

    #: HTTP::IN_X_FORWARDED_FOR_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    HTTP_IN_X_FORWARDED_FOR_HEADER = enum.auto()

    #: HTTP::IN_URL
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    HTTP_IN_URL = enum.auto()

    #: SMTP::IN_MAIL_FROM
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_MAIL_FROM = enum.auto()

    #: SMTP::IN_RCPT_TO
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_RCPT_TO = enum.auto()

    #: SMTP::IN_FROM
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_FROM = enum.auto()

    #: SMTP::IN_TO
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_TO = enum.auto()

    #: SMTP::IN_CC
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_CC = enum.auto()

    #: SMTP::IN_RECEIVED_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_RECEIVED_HEADER = enum.auto()

    #: SMTP::IN_REPLY_TO
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_REPLY_TO = enum.auto()

    #: SMTP::IN_X_ORIGINATING_IP_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_X_ORIGINATING_IP_HEADER = enum.auto()

    #: SMTP::IN_MESSAGE
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_MESSAGE = enum.auto()

    #: SSH::IN_SERVER_HOST_KEY
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SSH_IN_SERVER_HOST_KEY = enum.auto()

    #: SSL::IN_SERVER_NAME
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SSL_IN_SERVER_NAME = enum.auto()

    #: SMTP::IN_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMTP_IN_HEADER = enum.auto()

    #: X509::IN_CERT
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    X509_IN_CERT = enum.auto()

    #: SMB::IN_FILE_NAME
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    SMB_IN_FILE_NAME = enum.auto()

    #: SSH::SUCCESSFUL_LOGIN
    #: (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    #: An indicator of the login for the intel framework.
    SSH_SUCCESSFUL_LOGIN = enum.auto()
