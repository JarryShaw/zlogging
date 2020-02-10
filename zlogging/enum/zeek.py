# -*- coding: utf-8 -*-
"""Namespace: zeek.

:module: zlogging.enum.zeek
"""

from zlogging._compat import enum


@enum.unique
class layer3_proto(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'layer3_proto _'
    layer3_proto = vars()

    #: :currentmodule: zlogging.enum.zeek
    layer3_proto['L3_IPV4'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    layer3_proto['L3_IPV6'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    layer3_proto['L3_ARP'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    layer3_proto['L3_UNKNOWN'] = enum.auto()


@enum.unique
class link_encap(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'link_encap _'
    link_encap = vars()

    #: :currentmodule: zlogging.enum.zeek
    link_encap['LINK_ETHERNET'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    link_encap['LINK_UNKNOWN'] = enum.auto()


@enum.unique
class rpc_status(enum.IntFlag):
    """c.f. `base/bif/types.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/types.bif.zeek.html>`__"""

    _ignore_ = 'rpc_status _'
    rpc_status = vars()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_SUCCESS'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_PROG_UNAVAIL'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_PROG_MISMATCH'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_PROC_UNAVAIL'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_GARBAGE_ARGS'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_SYSTEM_ERR'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_TIMEOUT'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_VERS_MISMATCH'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_AUTH_ERROR'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    rpc_status['RPC_UNKNOWN_ERROR'] = enum.auto()


@enum.unique
class IPAddrAnonymization(enum.IntFlag):
    """See also: anonymize_addr

    c.f. `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html>`__

    """

    _ignore_ = 'IPAddrAnonymization _'
    IPAddrAnonymization = vars()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymization['KEEP_ORIG_ADDR'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymization['SEQUENTIALLY_NUMBERED'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymization['RANDOM_MD5'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymization['PREFIX_PRESERVING_A50'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymization['PREFIX_PRESERVING_MD5'] = enum.auto()


@enum.unique
class IPAddrAnonymizationClass(enum.IntFlag):
    """See also: anonymize_addr

    c.f. `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html>`__

    """

    _ignore_ = 'IPAddrAnonymizationClass _'
    IPAddrAnonymizationClass = vars()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymizationClass['ORIG_ADDR'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymizationClass['RESP_ADDR'] = enum.auto()

    #: :currentmodule: zlogging.enum.zeek
    IPAddrAnonymizationClass['OTHER_ADDR'] = enum.auto()


@enum.unique
class PcapFilterID(enum.IntFlag):
    """Enum type identifying dynamic BPF filters. These are used by
    Pcap::precompile_pcap_filter and Pcap::precompile_pcap_filter.

    c.f. `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html>`__

    """

    _ignore_ = 'PcapFilterID _'
    PcapFilterID = vars()

    #: :currentmodule: zlogging.enum.zeek
    PcapFilterID['None'] = enum.auto()

    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: :currentmodule: zlogging.enum.zeek
    PcapFilterID['PacketFilter::DefaultPcapFilter'] = enum.auto()

    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: :currentmodule: zlogging.enum.zeek
    PcapFilterID['PacketFilter::FilterTester'] = enum.auto()


@enum.unique
class pkt_profile_modes(enum.IntFlag):
    """Output modes for packet profiling information.

    See also: pkt_profile_mode, pkt_profile_freq, pkt_profile_file

    c.f. `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html>`__

    """

    _ignore_ = 'pkt_profile_modes _'
    pkt_profile_modes = vars()

    #: No output.
    #: :currentmodule: zlogging.enum.zeek
    pkt_profile_modes['PKT_PROFILE_MODE_NONE'] = enum.auto()

    #: Output every pkt_profile_freq seconds.
    #: :currentmodule: zlogging.enum.zeek
    pkt_profile_modes['PKT_PROFILE_MODE_SECS'] = enum.auto()

    #: Output every pkt_profile_freq packets.
    #: :currentmodule: zlogging.enum.zeek
    pkt_profile_modes['PKT_PROFILE_MODE_PKTS'] = enum.auto()

    #: Output every pkt_profile_freq bytes.
    #: :currentmodule: zlogging.enum.zeek
    pkt_profile_modes['PKT_PROFILE_MODE_BYTES'] = enum.auto()


@enum.unique
class transport_proto(enum.IntFlag):
    """A connection’s transport-layer protocol. Note that Zeek uses the term
    “connection” broadly, using flow semantics for ICMP and UDP.

    c.f. `base/init-bare.zeek <https://docs.zeek.org/en/stable/scripts/base/init-bare.zeek.html>`__

    """

    _ignore_ = 'transport_proto _'
    transport_proto = vars()

    #: An unknown transport-layer protocol.
    #: :currentmodule: zlogging.enum.zeek
    transport_proto['unknown_transport'] = enum.auto()

    #: TCP.
    #: :currentmodule: zlogging.enum.zeek
    transport_proto['tcp'] = enum.auto()

    #: UDP.
    #: :currentmodule: zlogging.enum.zeek
    transport_proto['udp'] = enum.auto()

    #: ICMP.
    #: :currentmodule: zlogging.enum.zeek
    transport_proto['icmp'] = enum.auto()


@enum.unique
class Direction(enum.IntFlag):
    """c.f. `base/utils/directions-and-hosts.zeek <https://docs.zeek.org/en/stable/scripts/base/utils/directions-and-hosts.zeek.html>`__"""

    _ignore_ = 'Direction _'
    Direction = vars()

    #: The connection originator is not within the locally-monitored
    #: network, but the other endpoint is.
    #: :currentmodule: zlogging.enum.zeek
    Direction['INBOUND'] = enum.auto()

    #: The connection originator is within the locally-monitored network,
    #: but the other endpoint is not.
    #: :currentmodule: zlogging.enum.zeek
    Direction['OUTBOUND'] = enum.auto()

    #: Only one endpoint is within the locally-monitored network, meaning
    #: the connection is either outbound or inbound.
    #: :currentmodule: zlogging.enum.zeek
    Direction['BIDIRECTIONAL'] = enum.auto()

    #: This value doesn’t match any connection.
    #: :currentmodule: zlogging.enum.zeek
    Direction['NO_DIRECTION'] = enum.auto()


@enum.unique
class Host(enum.IntFlag):
    """c.f. `base/utils/directions-and-hosts.zeek <https://docs.zeek.org/en/stable/scripts/base/utils/directions-and-hosts.zeek.html>`__"""

    _ignore_ = 'Host _'
    Host = vars()

    #: A host within the locally-monitored network.
    #: :currentmodule: zlogging.enum.zeek
    Host['LOCAL_HOSTS'] = enum.auto()

    #: A host not within the locally-monitored network.
    #: :currentmodule: zlogging.enum.zeek
    Host['REMOTE_HOSTS'] = enum.auto()

    #: Any host.
    #: :currentmodule: zlogging.enum.zeek
    Host['ALL_HOSTS'] = enum.auto()

    #: This value doesn’t match any host.
    #: :currentmodule: zlogging.enum.zeek
    Host['NO_HOSTS'] = enum.auto()
