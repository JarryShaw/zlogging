# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``PacketAnalyzer``."""

from zlogging._compat import enum


@enum.unique
class Tag(enum.IntFlag):
    """Enum: ``PacketAnalyzer::Tag``.

    See Also:
        `Packet Analyzers <https://docs.zeek.org/en/stable/scripts/Packet Analyzers.html#type-PacketAnalyzer::Tag>`__

    """

    _ignore_ = 'Tag _'
    Tag = vars()

    ANALYZER_ARP = enum.auto()

    ANALYZER_AYIYA = enum.auto()

    ANALYZER_ETHERNET = enum.auto()

    ANALYZER_FDDI = enum.auto()

    ANALYZER_GENEVE = enum.auto()

    ANALYZER_GRE = enum.auto()

    ANALYZER_GTPV1 = enum.auto()

    ANALYZER_ICMP = enum.auto()

    ANALYZER_IEEE802_11 = enum.auto()

    ANALYZER_IEEE802_11_RADIO = enum.auto()

    ANALYZER_IP = enum.auto()

    ANALYZER_IPTUNNEL = enum.auto()

    ANALYZER_LINUXSLL = enum.auto()

    ANALYZER_LINUXSLL2 = enum.auto()

    ANALYZER_LLC = enum.auto()

    ANALYZER_MPLS = enum.auto()

    ANALYZER_NFLOG = enum.auto()

    ANALYZER_NOVELL_802_3 = enum.auto()

    ANALYZER_NULL = enum.auto()

    ANALYZER_PBB = enum.auto()

    ANALYZER_PPP = enum.auto()

    ANALYZER_PPPOE = enum.auto()

    ANALYZER_PPPSERIAL = enum.auto()

    ANALYZER_ROOT = enum.auto()

    ANALYZER_SKIP = enum.auto()

    ANALYZER_SNAP = enum.auto()

    ANALYZER_IGMP = enum.auto()

    ANALYZER_TCP = enum.auto()

    ANALYZER_TEREDO = enum.auto()

    ANALYZER_UDP = enum.auto()

    ANALYZER_UNKNOWN_IP_TRANSPORT = enum.auto()

    ANALYZER_VLAN = enum.auto()

    ANALYZER_VNTAG = enum.auto()

    ANALYZER_VXLAN = enum.auto()
