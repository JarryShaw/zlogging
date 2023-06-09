# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Software``."""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """Enum: ``Software::Type``.

    Scripts detecting new types of software need to redef this enum to add their own specific software
    types which would then be used when they create ``Software::Info`` records.

    See Also:
        `base/frameworks/software/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/software/main.zeek.html#type-Software::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: A placeholder type for when the type of software is not known.
    UNKNOWN = enum.auto()

    #: OS::WINDOWS
    #: (present if policy/frameworks/software/windows-version-detection.zeek is loaded)
    #: Identifier for Windows operating system versions
    OS_WINDOWS = enum.auto()

    #: DHCP::SERVER
    #: (present if policy/protocols/dhcp/software.zeek is loaded)
    #: Identifier for web servers in the software framework.
    DHCP_SERVER = enum.auto()

    #: DHCP::CLIENT
    #: (present if policy/protocols/dhcp/software.zeek is loaded)
    #: Identifier for web browsers in the software framework.
    DHCP_CLIENT = enum.auto()

    #: FTP::CLIENT
    #: (present if policy/protocols/ftp/software.zeek is loaded)
    #: Identifier for FTP clients in the software framework.
    FTP_CLIENT = enum.auto()

    #: FTP::SERVER
    #: (present if policy/protocols/ftp/software.zeek is loaded)
    #: Not currently implemented.
    FTP_SERVER = enum.auto()

    #: HTTP::WEB_APPLICATION
    #: (present if policy/protocols/http/detect-webapps.zeek is loaded)
    #: Identifier for web applications in the software framework.
    HTTP_WEB_APPLICATION = enum.auto()

    #: HTTP::BROWSER_PLUGIN
    #: (present if policy/protocols/http/software-browser-plugins.zeek is loaded)
    #: Identifier for browser plugins in the software framework.
    HTTP_BROWSER_PLUGIN = enum.auto()

    #: HTTP::SERVER
    #: (present if policy/protocols/http/software.zeek is loaded)
    #: Identifier for web servers in the software framework.
    HTTP_SERVER = enum.auto()

    #: HTTP::APPSERVER
    #: (present if policy/protocols/http/software.zeek is loaded)
    #: Identifier for app servers in the software framework.
    HTTP_APPSERVER = enum.auto()

    #: HTTP::BROWSER
    #: (present if policy/protocols/http/software.zeek is loaded)
    #: Identifier for web browsers in the software framework.
    HTTP_BROWSER = enum.auto()

    #: MySQL::SERVER
    #: (present if policy/protocols/mysql/software.zeek is loaded)
    #: Identifier for MySQL servers in the software framework.
    MySQL_SERVER = enum.auto()

    #: SMTP::MAIL_CLIENT
    #: (present if policy/protocols/smtp/software.zeek is loaded)
    SMTP_MAIL_CLIENT = enum.auto()

    #: SMTP::MAIL_SERVER
    #: (present if policy/protocols/smtp/software.zeek is loaded)
    SMTP_MAIL_SERVER = enum.auto()

    #: SMTP::WEBMAIL_SERVER
    #: (present if policy/protocols/smtp/software.zeek is loaded)
    SMTP_WEBMAIL_SERVER = enum.auto()

    #: SSH::SERVER
    #: (present if policy/protocols/ssh/software.zeek is loaded)
    #: Identifier for SSH clients in the software framework.
    SSH_SERVER = enum.auto()

    #: SSH::CLIENT
    #: (present if policy/protocols/ssh/software.zeek is loaded)
    #: Identifier for SSH servers in the software framework.
    SSH_CLIENT = enum.auto()
