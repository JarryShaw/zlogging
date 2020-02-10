# -*- coding: utf-8 -*-
"""Namespace: ``Intel``."""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """Enum type to represent various types of intelligence data.

    c.f. `base/frameworks/intel/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: An IP address.
    Type['ADDR'] = enum.auto()

    #: A subnet in CIDR notation.
    Type['SUBNET'] = enum.auto()

    #: A complete URL without the prefix "http://".
    Type['URL'] = enum.auto()

    #: Software name.
    Type['SOFTWARE'] = enum.auto()

    #: Email address.
    Type['EMAIL'] = enum.auto()

    #: DNS domain name.
    Type['DOMAIN'] = enum.auto()

    #: A user name.
    Type['USER_NAME'] = enum.auto()

    #: Certificate SHA-1 hash.
    Type['CERT_HASH'] = enum.auto()

    #: Public key MD5 hash. (SSH server host keys are a good example.)
    Type['PUBKEY_HASH'] = enum.auto()

    #: (present if base/frameworks/intel/files.zeek is loaded)
    #: File hash which is non-hash type specific.  It’s up to the
    #: user to query for any relevant hash types.
    Type['FILE_HASH'] = enum.auto()

    #: (present if base/frameworks/intel/files.zeek is loaded)
    #: File name.  Typically with protocols with definite
    #: indications of a file name.
    Type['FILE_NAME'] = enum.auto()


@enum.unique
class Where(enum.IntFlag):
    """Enum to represent where data came from when it was discovered.
    The convention is to prefix the name with IN\_.

    c.f. `base/frameworks/intel/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Where>`__

    """

    _ignore_ = 'Where _'
    Where = vars()

    #: A catchall value to represent data of unknown provenance.
    Where['IN_ANYWHERE'] = enum.auto()

    #: Conn::IN_ORIG
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Conn__IN_ORIG'] = enum.auto()

    #: Conn::IN_RESP
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Conn__IN_RESP'] = enum.auto()

    #: Files::IN_HASH
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Files__IN_HASH'] = enum.auto()

    #: Files::IN_NAME
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Files__IN_NAME'] = enum.auto()

    #: DNS::IN_REQUEST
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['DNS__IN_REQUEST'] = enum.auto()

    #: DNS::IN_RESPONSE
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['DNS__IN_RESPONSE'] = enum.auto()

    #: HTTP::IN_HOST_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP__IN_HOST_HEADER'] = enum.auto()

    #: HTTP::IN_REFERRER_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP__IN_REFERRER_HEADER'] = enum.auto()

    #: HTTP::IN_USER_AGENT_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP__IN_USER_AGENT_HEADER'] = enum.auto()

    #: HTTP::IN_X_FORWARDED_FOR_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP__IN_X_FORWARDED_FOR_HEADER'] = enum.auto()

    #: HTTP::IN_URL
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP__IN_URL'] = enum.auto()

    #: SMTP::IN_MAIL_FROM
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_MAIL_FROM'] = enum.auto()

    #: SMTP::IN_RCPT_TO
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_RCPT_TO'] = enum.auto()

    #: SMTP::IN_FROM
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_FROM'] = enum.auto()

    #: SMTP::IN_TO
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_TO'] = enum.auto()

    #: SMTP::IN_CC
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_CC'] = enum.auto()

    #: SMTP::IN_RECEIVED_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_RECEIVED_HEADER'] = enum.auto()

    #: SMTP::IN_REPLY_TO
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_REPLY_TO'] = enum.auto()

    #: SMTP::IN_X_ORIGINATING_IP_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_X_ORIGINATING_IP_HEADER'] = enum.auto()

    #: SMTP::IN_MESSAGE
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_MESSAGE'] = enum.auto()

    #: SSH::IN_SERVER_HOST_KEY
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SSH__IN_SERVER_HOST_KEY'] = enum.auto()

    #: SSL::IN_SERVER_NAME
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SSL__IN_SERVER_NAME'] = enum.auto()

    #: SMTP::IN_HEADER
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP__IN_HEADER'] = enum.auto()

    #: X509::IN_CERT
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['X509__IN_CERT'] = enum.auto()

    #: SMB::IN_FILE_NAME
    #: (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMB__IN_FILE_NAME'] = enum.auto()

    #: SSH::SUCCESSFUL_LOGIN
    #: (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    #: An indicator of the login for the intel framework.
    Where['SSH__SUCCESSFUL_LOGIN'] = enum.auto()
