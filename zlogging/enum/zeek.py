# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``zeek``."""

from zlogging._compat import enum


@enum.unique
class TableChange(enum.IntFlag):
    """Enum: ``TableChange``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-TableChange>`__

    """

    _ignore_ = 'TableChange _'
    TableChange = vars()

    TABLE_ELEMENT_NEW = enum.auto()

    TABLE_ELEMENT_CHANGED = enum.auto()

    TABLE_ELEMENT_REMOVED = enum.auto()

    TABLE_ELEMENT_EXPIRED = enum.auto()


@enum.unique
class layer3_proto(enum.IntFlag):
    """Enum: ``layer3_proto``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-layer3_proto>`__

    """

    _ignore_ = 'layer3_proto _'
    layer3_proto = vars()

    L3_IPV4 = enum.auto()

    L3_IPV6 = enum.auto()

    L3_ARP = enum.auto()

    L3_UNKNOWN = enum.auto()


@enum.unique
class link_encap(enum.IntFlag):
    """Enum: ``link_encap``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-link_encap>`__

    """

    _ignore_ = 'link_encap _'
    link_encap = vars()

    LINK_ETHERNET = enum.auto()

    LINK_UNKNOWN = enum.auto()


@enum.unique
class rpc_status(enum.IntFlag):
    """Enum: ``rpc_status``.

    See Also:
        `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html#type-rpc_status>`__

    """

    _ignore_ = 'rpc_status _'
    rpc_status = vars()

    RPC_SUCCESS = enum.auto()

    RPC_PROG_UNAVAIL = enum.auto()

    RPC_PROG_MISMATCH = enum.auto()

    RPC_PROC_UNAVAIL = enum.auto()

    RPC_GARBAGE_ARGS = enum.auto()

    RPC_SYSTEM_ERR = enum.auto()

    RPC_TIMEOUT = enum.auto()

    RPC_VERS_MISMATCH = enum.auto()

    RPC_AUTH_ERROR = enum.auto()

    RPC_UNKNOWN_ERROR = enum.auto()


@enum.unique
class IPAddrAnonymization(enum.IntFlag):
    """Enum: ``IPAddrAnonymization``.

    See also: ``anonymize_addr``.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-IPAddrAnonymization>`__

    """

    _ignore_ = 'IPAddrAnonymization _'
    IPAddrAnonymization = vars()

    KEEP_ORIG_ADDR = enum.auto()

    SEQUENTIALLY_NUMBERED = enum.auto()

    RANDOM_MD5 = enum.auto()

    PREFIX_PRESERVING_A50 = enum.auto()

    PREFIX_PRESERVING_MD5 = enum.auto()


@enum.unique
class IPAddrAnonymizationClass(enum.IntFlag):
    """Enum: ``IPAddrAnonymizationClass``.

    See also: ``anonymize_addr``.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-IPAddrAnonymizationClass>`__

    """

    _ignore_ = 'IPAddrAnonymizationClass _'
    IPAddrAnonymizationClass = vars()

    ORIG_ADDR = enum.auto()

    RESP_ADDR = enum.auto()

    OTHER_ADDR = enum.auto()


@enum.unique
class PcapFilterID(enum.IntFlag):
    """Enum: ``PcapFilterID``.

    Enum type identifying dynamic BPF filters. These are used by ``Pcap::precompile_pcap_filter`` and
    ``Pcap::precompile_pcap_filter``.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-PcapFilterID>`__

    """

    _ignore_ = 'PcapFilterID _'
    PcapFilterID = vars()

    PcapFilterID['None'] = enum.auto()

    #: PacketFilter::DefaultPcapFilter
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    PacketFilter_DefaultPcapFilter = enum.auto()

    #: PacketFilter::FilterTester
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    PacketFilter_FilterTester = enum.auto()


@enum.unique
class pkt_profile_modes(enum.IntFlag):
    """Enum: ``pkt_profile_modes``.

    Output modes for packet profiling information.

    See also: ``pkt_profile_mode``, ``pkt_profile_freq``, ``pkt_profile_file``.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-pkt_profile_modes>`__

    """

    _ignore_ = 'pkt_profile_modes _'
    pkt_profile_modes = vars()

    #: No output.
    PKT_PROFILE_MODE_NONE = enum.auto()

    #: Output every pkt\_profile\_freq seconds.
    PKT_PROFILE_MODE_SECS = enum.auto()

    #: Output every pkt\_profile\_freq packets.
    PKT_PROFILE_MODE_PKTS = enum.auto()

    #: Output every pkt\_profile\_freq bytes.
    PKT_PROFILE_MODE_BYTES = enum.auto()


@enum.unique
class transport_proto(enum.IntFlag):
    """Enum: ``transport_proto``.

    A connection’s transport-layer protocol. Note that Zeek uses the term “connection” broadly, using
    flow semantics for ICMP and UDP.

    See Also:
        `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html#type-transport_proto>`__

    """

    _ignore_ = 'transport_proto _'
    transport_proto = vars()

    #: An unknown transport-layer protocol.
    unknown_transport = enum.auto()

    #: TCP.
    tcp = enum.auto()

    #: UDP.
    udp = enum.auto()

    #: ICMP.
    icmp = enum.auto()


@enum.unique
class Direction(enum.IntFlag):
    """Enum: ``Direction``.

    See Also:
        `base/utils/directions-and-hosts.zeek <https://docs.zeek.org/en/stable/scripts/base/utils/directions-and-hosts.zeek.html#type-Direction>`__

    """

    _ignore_ = 'Direction _'
    Direction = vars()

    #: The connection originator is not within the locally-monitored
    #: network, but the other endpoint is.
    INBOUND = enum.auto()

    #: The connection originator is within the locally-monitored network,
    #: but the other endpoint is not.
    OUTBOUND = enum.auto()

    #: Only one endpoint is within the locally-monitored network, meaning
    #: the connection is either outbound or inbound.
    BIDIRECTIONAL = enum.auto()

    #: This value doesn’t match any connection.
    NO_DIRECTION = enum.auto()


@enum.unique
class Host(enum.IntFlag):
    """Enum: ``Host``.

    See Also:
        `base/utils/directions-and-hosts.zeek <https://docs.zeek.org/en/stable/scripts/base/utils/directions-and-hosts.zeek.html#type-Host>`__

    """

    _ignore_ = 'Host _'
    Host = vars()

    #: A host within the locally-monitored network.
    LOCAL_HOSTS = enum.auto()

    #: A host not within the locally-monitored network.
    REMOTE_HOSTS = enum.auto()

    #: Any host.
    ALL_HOSTS = enum.auto()

    #: This value doesn’t match any host.
    NO_HOSTS = enum.auto()
