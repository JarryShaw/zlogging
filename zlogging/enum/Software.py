# -*- coding: utf-8 -*-
"""Namespace: ``Software``."""

from zlogging._compat import enum


@enum.unique
class Type(enum.IntFlag):
    """Scripts detecting new types of software need to redef this enum to add
    their own specific software types which would then be used when they
    create Software::Info records.

    c.f. `base/frameworks/software/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/software/main.zeek.html#type-Software::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: A placeholder type for when the type of software is not known.
    Type['UNKNOWN'] = enum.auto()

    #: OS::WINDOWS
    #: (present if policy/frameworks/software/windows-version-detection.zeek is loaded)
    #: Identifier for Windows operating system versions
    Type['OS__WINDOWS'] = enum.auto()

    #: DHCP::SERVER
    #: (present if policy/protocols/dhcp/software.zeek is loaded)
    #: Identifier for web servers in the software framework.
    Type['DHCP__SERVER'] = enum.auto()

    #: DHCP::CLIENT
    #: (present if policy/protocols/dhcp/software.zeek is loaded)
    #: Identifier for web browsers in the software framework.
    Type['DHCP__CLIENT'] = enum.auto()

    #: FTP::CLIENT
    #: (present if policy/protocols/ftp/software.zeek is loaded)
    #: Identifier for FTP clients in the software framework.
    Type['FTP__CLIENT'] = enum.auto()

    #: FTP::SERVER
    #: (present if policy/protocols/ftp/software.zeek is loaded)
    #: Not currently implemented.
    Type['FTP__SERVER'] = enum.auto()

    #: HTTP::WEB_APPLICATION
    #: (present if policy/protocols/http/detect-webapps.zeek is loaded)
    #: Identifier for web applications in the software framework.
    Type['HTTP__WEB_APPLICATION'] = enum.auto()

    #: HTTP::BROWSER_PLUGIN
    #: (present if policy/protocols/http/software-browser-plugins.zeek is loaded)
    #: Identifier for browser plugins in the software framework.
    Type['HTTP__BROWSER_PLUGIN'] = enum.auto()

    #: HTTP::SERVER
    #: (present if policy/protocols/http/software.zeek is loaded)
    #: Identifier for web servers in the software framework.
    Type['HTTP__SERVER'] = enum.auto()

    #: HTTP::APPSERVER
    #: (present if policy/protocols/http/software.zeek is loaded)
    #: Identifier for app servers in the software framework.
    Type['HTTP__APPSERVER'] = enum.auto()

    #: HTTP::BROWSER
    #: (present if policy/protocols/http/software.zeek is loaded)
    #: Identifier for web browsers in the software framework.
    Type['HTTP__BROWSER'] = enum.auto()

    #: MySQL::SERVER
    #: (present if policy/protocols/mysql/software.zeek is loaded)
    #: Identifier for MySQL servers in the software framework.
    Type['MySQL__SERVER'] = enum.auto()

    #: SMTP::MAIL_CLIENT
    #: (present if policy/protocols/smtp/software.zeek is loaded)
    Type['SMTP__MAIL_CLIENT'] = enum.auto()

    #: SMTP::MAIL_SERVER
    #: (present if policy/protocols/smtp/software.zeek is loaded)
    Type['SMTP__MAIL_SERVER'] = enum.auto()

    #: SMTP::WEBMAIL_SERVER
    #: (present if policy/protocols/smtp/software.zeek is loaded)
    Type['SMTP__WEBMAIL_SERVER'] = enum.auto()

    #: SSH::SERVER
    #: (present if policy/protocols/ssh/software.zeek is loaded)
    #: Identifier for SSH clients in the software framework.
    Type['SSH__SERVER'] = enum.auto()

    #: SSH::CLIENT
    #: (present if policy/protocols/ssh/software.zeek is loaded)
    #: Identifier for SSH servers in the software framework.
    Type['SSH__CLIENT'] = enum.auto()
