# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``AllAnalyzers``."""

from zlogging._compat import enum


@enum.unique
class Tag(enum.IntFlag):
    """Enum: ``AllAnalyzers::Tag``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-AllAnalyzers::Tag>`__

    """

    _ignore_ = 'Tag _'
    Tag = vars()

    PACKETANALYZER_ANALYZER_ARP = enum.auto()

    PACKETANALYZER_ANALYZER_AYIYA = enum.auto()

    ANALYZER_ANALYZER_BITTORRENT = enum.auto()

    ANALYZER_ANALYZER_BITTORRENTTRACKER = enum.auto()

    ANALYZER_ANALYZER_CONNSIZE = enum.auto()

    ANALYZER_ANALYZER_DCE_RPC = enum.auto()

    ANALYZER_ANALYZER_DHCP = enum.auto()

    ANALYZER_ANALYZER_DNP3_TCP = enum.auto()

    ANALYZER_ANALYZER_DNP3_UDP = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_DNS = enum.auto()

    ANALYZER_ANALYZER_DNS = enum.auto()

    PACKETANALYZER_ANALYZER_ETHERNET = enum.auto()

    PACKETANALYZER_ANALYZER_FDDI = enum.auto()

    ANALYZER_ANALYZER_FTP_DATA = enum.auto()

    FILES_ANALYZER_DATA_EVENT = enum.auto()

    FILES_ANALYZER_ENTROPY = enum.auto()

    FILES_ANALYZER_EXTRACT = enum.auto()

    FILES_ANALYZER_MD5 = enum.auto()

    FILES_ANALYZER_SHA1 = enum.auto()

    FILES_ANALYZER_SHA224 = enum.auto()

    FILES_ANALYZER_SHA256 = enum.auto()

    FILES_ANALYZER_SHA384 = enum.auto()

    FILES_ANALYZER_SHA512 = enum.auto()

    ANALYZER_ANALYZER_FTP = enum.auto()

    ANALYZER_ANALYZER_FTP_ADAT = enum.auto()

    PACKETANALYZER_ANALYZER_GENEVE = enum.auto()

    ANALYZER_ANALYZER_GNUTELLA = enum.auto()

    PACKETANALYZER_ANALYZER_GRE = enum.auto()

    ANALYZER_ANALYZER_GSSAPI = enum.auto()

    PACKETANALYZER_ANALYZER_GTPV1 = enum.auto()

    ANALYZER_ANALYZER_HTTP = enum.auto()

    PACKETANALYZER_ANALYZER_ICMP = enum.auto()

    ANALYZER_ANALYZER_ICMP = enum.auto()

    ANALYZER_ANALYZER_IDENT = enum.auto()

    PACKETANALYZER_ANALYZER_IEEE802_11 = enum.auto()

    PACKETANALYZER_ANALYZER_IEEE802_11_RADIO = enum.auto()

    ANALYZER_ANALYZER_IMAP = enum.auto()

    PACKETANALYZER_ANALYZER_IP = enum.auto()

    PACKETANALYZER_ANALYZER_IPTUNNEL = enum.auto()

    ANALYZER_ANALYZER_IRC = enum.auto()

    ANALYZER_ANALYZER_IRC_DATA = enum.auto()

    ANALYZER_ANALYZER_KRB = enum.auto()

    ANALYZER_ANALYZER_KRB_TCP = enum.auto()

    PACKETANALYZER_ANALYZER_LINUXSLL = enum.auto()

    PACKETANALYZER_ANALYZER_LINUXSLL2 = enum.auto()

    PACKETANALYZER_ANALYZER_LLC = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_RLOGIN = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_RSH = enum.auto()

    ANALYZER_ANALYZER_LOGIN = enum.auto()

    ANALYZER_ANALYZER_NVT = enum.auto()

    ANALYZER_ANALYZER_RLOGIN = enum.auto()

    ANALYZER_ANALYZER_RSH = enum.auto()

    ANALYZER_ANALYZER_TELNET = enum.auto()

    ANALYZER_ANALYZER_MODBUS = enum.auto()

    PACKETANALYZER_ANALYZER_MPLS = enum.auto()

    ANALYZER_ANALYZER_MQTT = enum.auto()

    ANALYZER_ANALYZER_MYSQL = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_NCP = enum.auto()

    ANALYZER_ANALYZER_NCP = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_NETBIOSSSN = enum.auto()

    ANALYZER_ANALYZER_NETBIOSSSN = enum.auto()

    PACKETANALYZER_ANALYZER_NFLOG = enum.auto()

    PACKETANALYZER_ANALYZER_NOVELL_802_3 = enum.auto()

    ANALYZER_ANALYZER_NTLM = enum.auto()

    ANALYZER_ANALYZER_NTP = enum.auto()

    PACKETANALYZER_ANALYZER_NULL = enum.auto()

    PACKETANALYZER_ANALYZER_PBB = enum.auto()

    FILES_ANALYZER_PE = enum.auto()

    ANALYZER_ANALYZER_PIA_TCP = enum.auto()

    ANALYZER_ANALYZER_PIA_UDP = enum.auto()

    ANALYZER_ANALYZER_POP3 = enum.auto()

    PACKETANALYZER_ANALYZER_PPP = enum.auto()

    PACKETANALYZER_ANALYZER_PPPOE = enum.auto()

    PACKETANALYZER_ANALYZER_PPPSERIAL = enum.auto()

    ANALYZER_ANALYZER_RADIUS = enum.auto()

    ANALYZER_ANALYZER_RDP = enum.auto()

    ANALYZER_ANALYZER_RDPEUDP = enum.auto()

    ANALYZER_ANALYZER_RFB = enum.auto()

    PACKETANALYZER_ANALYZER_ROOT = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_NFS = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_RPC = enum.auto()

    ANALYZER_ANALYZER_MOUNT = enum.auto()

    ANALYZER_ANALYZER_NFS = enum.auto()

    ANALYZER_ANALYZER_PORTMAPPER = enum.auto()

    ANALYZER_ANALYZER_SIP = enum.auto()

    PACKETANALYZER_ANALYZER_SKIP = enum.auto()

    ANALYZER_ANALYZER_CONTENTS_SMB = enum.auto()

    ANALYZER_ANALYZER_SMB = enum.auto()

    ANALYZER_ANALYZER_SMTP = enum.auto()

    ANALYZER_ANALYZER_SMTP_BDAT = enum.auto()

    PACKETANALYZER_ANALYZER_SNAP = enum.auto()

    ANALYZER_ANALYZER_SNMP = enum.auto()

    ANALYZER_ANALYZER_SOCKS = enum.auto()

    ANALYZER_ANALYZER_FINGER = enum.auto()

    ANALYZER_ANALYZER_LDAP_TCP = enum.auto()

    ANALYZER_ANALYZER_LDAP_UDP = enum.auto()

    ANALYZER_ANALYZER_POSTGRESQL = enum.auto()

    ANALYZER_ANALYZER_QUIC = enum.auto()

    ANALYZER_ANALYZER_REDIS = enum.auto()

    ANALYZER_ANALYZER_SYSLOG = enum.auto()

    ANALYZER_ANALYZER_SPICY_WEBSOCKET = enum.auto()

    PACKETANALYZER_ANALYZER_IGMP = enum.auto()

    ANALYZER_ANALYZER_SSH = enum.auto()

    ANALYZER_ANALYZER_DTLS = enum.auto()

    ANALYZER_ANALYZER_SSL = enum.auto()

    ANALYZER_ANALYZER_STREAM_EVENT = enum.auto()

    ANALYZER_ANALYZER_CONTENTLINE = enum.auto()

    ANALYZER_ANALYZER_CONTENTS = enum.auto()

    ANALYZER_ANALYZER_TCPSTATS = enum.auto()

    PACKETANALYZER_ANALYZER_TCP = enum.auto()

    ANALYZER_ANALYZER_TCP = enum.auto()

    PACKETANALYZER_ANALYZER_TEREDO = enum.auto()

    PACKETANALYZER_ANALYZER_UDP = enum.auto()

    ANALYZER_ANALYZER_UDP = enum.auto()

    PACKETANALYZER_ANALYZER_UNKNOWN_IP_TRANSPORT = enum.auto()

    ANALYZER_ANALYZER_UNKNOWN_IP_TRANSPORT = enum.auto()

    PACKETANALYZER_ANALYZER_VLAN = enum.auto()

    PACKETANALYZER_ANALYZER_VNTAG = enum.auto()

    PACKETANALYZER_ANALYZER_VXLAN = enum.auto()

    ANALYZER_ANALYZER_WEBSOCKET = enum.auto()

    FILES_ANALYZER_OCSP_REPLY = enum.auto()

    FILES_ANALYZER_OCSP_REQUEST = enum.auto()

    FILES_ANALYZER_X509 = enum.auto()

    ANALYZER_ANALYZER_XMPP = enum.auto()

    ANALYZER_ANALYZER_ZIP = enum.auto()
