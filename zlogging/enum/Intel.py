# -*- coding: utf-8 -*-
"""Namespace: Intel."""

import enum


@enum.unique
class Type(enum.IntFlag):
    """Enum type to represent various types of intelligence data.

    
    c.f. `base/frameworks/intel/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html>`__
    """

    _ignore_ = 'Type _'
    Type = vars()

    # An IP address.
    Type['ADDR'] = enum.auto()

    # A subnet in CIDR notation.
    Type['SUBNET'] = enum.auto()

    # A complete URL without the prefix "http://".
    Type['URL'] = enum.auto()

    # Software name.
    Type['SOFTWARE'] = enum.auto()

    # Email address.
    Type['EMAIL'] = enum.auto()

    # DNS domain name.
    Type['DOMAIN'] = enum.auto()

    # A user name.
    Type['USER_NAME'] = enum.auto()

    # Certificate SHA-1 hash.
    Type['CERT_HASH'] = enum.auto()

    # Public key MD5 hash. (SSH server host keys are a good example.)
    Type['PUBKEY_HASH'] = enum.auto()

    # (present if base/frameworks/intel/files.zeek is loaded)
    # File hash which is non-hash type specific.  It’s up to the
    # user to query for any relevant hash types.
    Type['FILE_HASH'] = enum.auto()

    # (present if base/frameworks/intel/files.zeek is loaded)
    # File name.  Typically with protocols with definite
    # indications of a file name.
    Type['FILE_NAME'] = enum.auto()


@enum.unique
class Where(enum.IntFlag):
    """Enum to represent where data came from when it was discovered.
    The convention is to prefix the name with IN_.

    
    c.f. `base/frameworks/intel/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html>`__
    """

    _ignore_ = 'Where _'
    Where = vars()

    # A catchall value to represent data of unknown provenance.
    Where['IN_ANYWHERE'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Conn::IN_ORIG'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Conn::IN_RESP'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Files::IN_HASH'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['Files::IN_NAME'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['DNS::IN_REQUEST'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['DNS::IN_RESPONSE'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP::IN_HOST_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP::IN_REFERRER_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP::IN_USER_AGENT_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP::IN_X_FORWARDED_FOR_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['HTTP::IN_URL'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_MAIL_FROM'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_RCPT_TO'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_FROM'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_TO'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_CC'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_RECEIVED_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_REPLY_TO'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_X_ORIGINATING_IP_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_MESSAGE'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SSH::IN_SERVER_HOST_KEY'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SSL::IN_SERVER_NAME'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMTP::IN_HEADER'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['X509::IN_CERT'] = enum.auto()

    # (present if policy/frameworks/intel/seen/where-locations.zeek is loaded)
    Where['SMB::IN_FILE_NAME'] = enum.auto()

    # (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    # An indicator of the login for the intel framework.
    Where['SSH::SUCCESSFUL_LOGIN'] = enum.auto()
