# -*- coding: utf-8 -*-
"""Namespace: Software."""

import enum


@enum.unique
class Type(enum.IntFlag):
    """Scripts detecting new types of software need to redef this enum to add
    their own specific software types which would then be used when they
    create Software::Info records.

    
    c.f. `base/frameworks/software/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/software/main.zeek.html>`__
    """

    _ignore_ = 'Type _'
    Type = vars()

    # A placeholder type for when the type of software is not known.
    Type['UNKNOWN'] = enum.auto()

    # (present if policy/frameworks/software/windows-version-detection.zeek is loaded)
    # Identifier for Windows operating system versions
    Type['OS::WINDOWS'] = enum.auto()

    # (present if policy/protocols/dhcp/software.zeek is loaded)
    # Identifier for web servers in the software framework.
    Type['DHCP::SERVER'] = enum.auto()

    # (present if policy/protocols/dhcp/software.zeek is loaded)
    # Identifier for web browsers in the software framework.
    Type['DHCP::CLIENT'] = enum.auto()

    # (present if policy/protocols/ftp/software.zeek is loaded)
    # Identifier for FTP clients in the software framework.
    Type['FTP::CLIENT'] = enum.auto()

    # (present if policy/protocols/ftp/software.zeek is loaded)
    # Not currently implemented.
    Type['FTP::SERVER'] = enum.auto()

    # (present if policy/protocols/http/detect-webapps.zeek is loaded)
    # Identifier for web applications in the software framework.
    Type['HTTP::WEB_APPLICATION'] = enum.auto()

    # (present if policy/protocols/http/software-browser-plugins.zeek is loaded)
    # Identifier for browser plugins in the software framework.
    Type['HTTP::BROWSER_PLUGIN'] = enum.auto()

    # (present if policy/protocols/http/software.zeek is loaded)
    # Identifier for web servers in the software framework.
    Type['HTTP::SERVER'] = enum.auto()

    # (present if policy/protocols/http/software.zeek is loaded)
    # Identifier for app servers in the software framework.
    Type['HTTP::APPSERVER'] = enum.auto()

    # (present if policy/protocols/http/software.zeek is loaded)
    # Identifier for web browsers in the software framework.
    Type['HTTP::BROWSER'] = enum.auto()

    # (present if policy/protocols/mysql/software.zeek is loaded)
    # Identifier for MySQL servers in the software framework.
    Type['MySQL::SERVER'] = enum.auto()

    # (present if policy/protocols/smtp/software.zeek is loaded)
    Type['SMTP::MAIL_CLIENT'] = enum.auto()

    # (present if policy/protocols/smtp/software.zeek is loaded)
    Type['SMTP::MAIL_SERVER'] = enum.auto()

    # (present if policy/protocols/smtp/software.zeek is loaded)
    Type['SMTP::WEBMAIL_SERVER'] = enum.auto()

    # (present if policy/protocols/ssh/software.zeek is loaded)
    # Identifier for SSH clients in the software framework.
    Type['SSH::SERVER'] = enum.auto()

    # (present if policy/protocols/ssh/software.zeek is loaded)
    # Identifier for SSH servers in the software framework.
    Type['SSH::CLIENT'] = enum.auto()
