# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Analyzer``."""

from zlogging._compat import enum


@enum.unique
class Tag(enum.IntFlag):
    """Enum: ``Analyzer::Tag``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-Analyzer::Tag>`__

    """

    _ignore_ = 'Tag _'
    Tag = vars()

    ANALYZER_BITTORRENT = enum.auto()

    ANALYZER_BITTORRENTTRACKER = enum.auto()

    ANALYZER_CONNSIZE = enum.auto()

    ANALYZER_DCE_RPC = enum.auto()

    ANALYZER_DHCP = enum.auto()

    ANALYZER_DNP3_TCP = enum.auto()

    ANALYZER_DNP3_UDP = enum.auto()

    ANALYZER_CONTENTS_DNS = enum.auto()

    ANALYZER_DNS = enum.auto()

    ANALYZER_FTP_DATA = enum.auto()

    ANALYZER_FTP = enum.auto()

    ANALYZER_FTP_ADAT = enum.auto()

    ANALYZER_GNUTELLA = enum.auto()

    ANALYZER_GSSAPI = enum.auto()

    ANALYZER_HTTP = enum.auto()

    ANALYZER_ICMP = enum.auto()

    ANALYZER_IDENT = enum.auto()

    ANALYZER_IMAP = enum.auto()

    ANALYZER_IRC = enum.auto()

    ANALYZER_IRC_DATA = enum.auto()

    ANALYZER_KRB = enum.auto()

    ANALYZER_KRB_TCP = enum.auto()

    ANALYZER_CONTENTS_RLOGIN = enum.auto()

    ANALYZER_CONTENTS_RSH = enum.auto()

    ANALYZER_LOGIN = enum.auto()

    ANALYZER_NVT = enum.auto()

    ANALYZER_RLOGIN = enum.auto()

    ANALYZER_RSH = enum.auto()

    ANALYZER_TELNET = enum.auto()

    ANALYZER_MODBUS = enum.auto()

    ANALYZER_MQTT = enum.auto()

    ANALYZER_MYSQL = enum.auto()

    ANALYZER_CONTENTS_NCP = enum.auto()

    ANALYZER_NCP = enum.auto()

    ANALYZER_CONTENTS_NETBIOSSSN = enum.auto()

    ANALYZER_NETBIOSSSN = enum.auto()

    ANALYZER_NTLM = enum.auto()

    ANALYZER_NTP = enum.auto()

    ANALYZER_PIA_TCP = enum.auto()

    ANALYZER_PIA_UDP = enum.auto()

    ANALYZER_POP3 = enum.auto()

    ANALYZER_RADIUS = enum.auto()

    ANALYZER_RDP = enum.auto()

    ANALYZER_RDPEUDP = enum.auto()

    ANALYZER_RFB = enum.auto()

    ANALYZER_CONTENTS_NFS = enum.auto()

    ANALYZER_CONTENTS_RPC = enum.auto()

    ANALYZER_MOUNT = enum.auto()

    ANALYZER_NFS = enum.auto()

    ANALYZER_PORTMAPPER = enum.auto()

    ANALYZER_SIP = enum.auto()

    ANALYZER_CONTENTS_SMB = enum.auto()

    ANALYZER_SMB = enum.auto()

    ANALYZER_SMTP = enum.auto()

    ANALYZER_SMTP_BDAT = enum.auto()

    ANALYZER_SNMP = enum.auto()

    ANALYZER_SOCKS = enum.auto()

    ANALYZER_FINGER = enum.auto()

    ANALYZER_LDAP_TCP = enum.auto()

    ANALYZER_LDAP_UDP = enum.auto()

    ANALYZER_POSTGRESQL = enum.auto()

    ANALYZER_QUIC = enum.auto()

    ANALYZER_REDIS = enum.auto()

    ANALYZER_SYSLOG = enum.auto()

    ANALYZER_SPICY_WEBSOCKET = enum.auto()

    ANALYZER_SSH = enum.auto()

    ANALYZER_DTLS = enum.auto()

    ANALYZER_SSL = enum.auto()

    ANALYZER_STREAM_EVENT = enum.auto()

    ANALYZER_CONTENTLINE = enum.auto()

    ANALYZER_CONTENTS = enum.auto()

    ANALYZER_TCPSTATS = enum.auto()

    ANALYZER_TCP = enum.auto()

    ANALYZER_UDP = enum.auto()

    ANALYZER_UNKNOWN_IP_TRANSPORT = enum.auto()

    ANALYZER_WEBSOCKET = enum.auto()

    ANALYZER_XMPP = enum.auto()

    ANALYZER_ZIP = enum.auto()
