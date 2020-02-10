# -*- coding: utf-8 -*-
"""Namespace: Log."""

import enum


@enum.unique
class ID(enum.IntFlag):
    """Type that defines an ID unique to each log stream. Scripts creating new
    log streams need to redef this enum to add their own specific log ID.
    The log ID implicitly determines the default name of the generated log
    file.

    
    c.f. `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html>`__
    """

    _ignore_ = 'ID _'
    ID = vars()

    # Dummy place-holder.
    ID['UNKNOWN'] = enum.auto()

    # (present if base/frameworks/broker/log.zeek is loaded)
    ID['Broker::LOG'] = enum.auto()

    # (present if base/frameworks/files/main.zeek is loaded)
    # Logging stream for file analysis.
    ID['Files::LOG'] = enum.auto()

    # (present if base/frameworks/reporter/main.zeek is loaded)
    ID['Reporter::LOG'] = enum.auto()

    # (present if base/frameworks/cluster/main.zeek is loaded)
    ID['Cluster::LOG'] = enum.auto()

    # (present if base/frameworks/notice/main.zeek is loaded)
    # This is the primary logging stream for notices.
    ID['Notice::LOG'] = enum.auto()

    # (present if base/frameworks/notice/main.zeek is loaded)
    # This is the alarm stream.
    ID['Notice::ALARM_LOG'] = enum.auto()

    # (present if base/frameworks/notice/weird.zeek is loaded)
    ID['Weird::LOG'] = enum.auto()

    # (present if base/frameworks/dpd/main.zeek is loaded)
    ID['DPD::LOG'] = enum.auto()

    # (present if base/frameworks/signatures/main.zeek is loaded)
    ID['Signatures::LOG'] = enum.auto()

    # (present if base/frameworks/packet-filter/main.zeek is loaded)
    ID['PacketFilter::LOG'] = enum.auto()

    # (present if base/frameworks/software/main.zeek is loaded)
    ID['Software::LOG'] = enum.auto()

    # (present if base/frameworks/intel/main.zeek is loaded)
    ID['Intel::LOG'] = enum.auto()

    # (present if base/frameworks/config/main.zeek is loaded)
    ID['Config::LOG'] = enum.auto()

    # (present if base/frameworks/tunnels/main.zeek is loaded)
    ID['Tunnel::LOG'] = enum.auto()

    # (present if base/frameworks/openflow/plugins/log.zeek is loaded)
    ID['OpenFlow::LOG'] = enum.auto()

    # (present if base/frameworks/netcontrol/main.zeek is loaded)
    ID['NetControl::LOG'] = enum.auto()

    # (present if base/frameworks/netcontrol/types.zeek is loaded)
    # Stop forwarding all packets matching the entity.
    # No additional arguments.
    ID['NetControl::DROP'] = enum.auto()

    # (present if base/frameworks/netcontrol/shunt.zeek is loaded)
    ID['NetControl::SHUNT'] = enum.auto()

    # (present if base/protocols/conn/main.zeek is loaded)
    ID['Conn::LOG'] = enum.auto()

    # (present if base/protocols/dce-rpc/main.zeek is loaded)
    ID['DCE_RPC::LOG'] = enum.auto()

    # (present if base/protocols/dhcp/main.zeek is loaded)
    ID['DHCP::LOG'] = enum.auto()

    # (present if base/protocols/dnp3/main.zeek is loaded)
    ID['DNP3::LOG'] = enum.auto()

    # (present if base/protocols/dns/main.zeek is loaded)
    ID['DNS::LOG'] = enum.auto()

    # (present if base/protocols/ftp/main.zeek is loaded)
    ID['FTP::LOG'] = enum.auto()

    # (present if base/protocols/ssl/main.zeek is loaded)
    ID['SSL::LOG'] = enum.auto()

    # (present if base/files/x509/main.zeek is loaded)
    ID['X509::LOG'] = enum.auto()

    # (present if base/protocols/http/main.zeek is loaded)
    ID['HTTP::LOG'] = enum.auto()

    # (present if base/protocols/irc/main.zeek is loaded)
    ID['IRC::LOG'] = enum.auto()

    # (present if base/protocols/krb/main.zeek is loaded)
    ID['KRB::LOG'] = enum.auto()

    # (present if base/protocols/modbus/main.zeek is loaded)
    ID['Modbus::LOG'] = enum.auto()

    # (present if base/protocols/mysql/main.zeek is loaded)
    ID['mysql::LOG'] = enum.auto()

    # (present if base/protocols/ntlm/main.zeek is loaded)
    ID['NTLM::LOG'] = enum.auto()

    # (present if base/protocols/ntp/main.zeek is loaded)
    ID['NTP::LOG'] = enum.auto()

    # (present if base/protocols/radius/main.zeek is loaded)
    ID['RADIUS::LOG'] = enum.auto()

    # (present if base/protocols/rdp/main.zeek is loaded)
    ID['RDP::LOG'] = enum.auto()

    # (present if base/protocols/rfb/main.zeek is loaded)
    ID['RFB::LOG'] = enum.auto()

    # (present if base/protocols/sip/main.zeek is loaded)
    ID['SIP::LOG'] = enum.auto()

    # (present if base/protocols/snmp/main.zeek is loaded)
    ID['SNMP::LOG'] = enum.auto()

    # (present if base/protocols/smb/main.zeek is loaded)
    ID['SMB::AUTH_LOG'] = enum.auto()

    # (present if base/protocols/smb/main.zeek is loaded)
    ID['SMB::MAPPING_LOG'] = enum.auto()

    # (present if base/protocols/smb/main.zeek is loaded)
    ID['SMB::FILES_LOG'] = enum.auto()

    # (present if base/protocols/smtp/main.zeek is loaded)
    ID['SMTP::LOG'] = enum.auto()

    # (present if base/protocols/socks/main.zeek is loaded)
    ID['SOCKS::LOG'] = enum.auto()

    # (present if base/protocols/ssh/main.zeek is loaded)
    ID['SSH::LOG'] = enum.auto()

    # (present if base/protocols/syslog/main.zeek is loaded)
    ID['Syslog::LOG'] = enum.auto()

    # (present if base/files/pe/main.zeek is loaded)
    ID['PE::LOG'] = enum.auto()

    # (present if policy/frameworks/netcontrol/catch-and-release.zeek is loaded)
    ID['NetControl::CATCH_RELEASE'] = enum.auto()

    # (present if policy/files/unified2/main.zeek is loaded)
    ID['Unified2::LOG'] = enum.auto()

    # (present if policy/files/x509/log-ocsp.zeek is loaded)
    ID['OCSP::LOG'] = enum.auto()

    # (present if policy/integration/barnyard2/main.zeek is loaded)
    ID['Barnyard2::LOG'] = enum.auto()

    # (present if policy/misc/capture-loss.zeek is loaded)
    ID['CaptureLoss::LOG'] = enum.auto()

    # (present if policy/misc/detect-traceroute/main.zeek is loaded)
    ID['Traceroute::LOG'] = enum.auto()

    # (present if policy/misc/loaded-scripts.zeek is loaded)
    ID['LoadedScripts::LOG'] = enum.auto()

    # (present if policy/misc/stats.zeek is loaded)
    ID['Stats::LOG'] = enum.auto()

    # (present if policy/misc/weird-stats.zeek is loaded)
    ID['WeirdStats::LOG'] = enum.auto()

    # (present if policy/protocols/conn/known-hosts.zeek is loaded)
    ID['Known::HOSTS_LOG'] = enum.auto()

    # (present if policy/protocols/conn/known-services.zeek is loaded)
    ID['Known::SERVICES_LOG'] = enum.auto()

    # (present if policy/protocols/modbus/known-masters-slaves.zeek is loaded)
    ID['Known::MODBUS_LOG'] = enum.auto()

    # (present if policy/protocols/modbus/track-memmap.zeek is loaded)
    ID['Modbus::REGISTER_CHANGE_LOG'] = enum.auto()

    # (present if policy/protocols/mqtt/main.zeek is loaded)
    ID['MQTT::CONNECT_LOG'] = enum.auto()

    # (present if policy/protocols/mqtt/main.zeek is loaded)
    ID['MQTT::SUBSCRIBE_LOG'] = enum.auto()

    # (present if policy/protocols/mqtt/main.zeek is loaded)
    ID['MQTT::PUBLISH_LOG'] = enum.auto()

    # (present if policy/protocols/smb/log-cmds.zeek is loaded)
    ID['SMB::CMD_LOG'] = enum.auto()

    # (present if policy/protocols/ssl/known-certs.zeek is loaded)
    ID['Known::CERTS_LOG'] = enum.auto()

    # (present if zeekygen/example.zeek is loaded)
    ID['ZeekygenExample::LOG'] = enum.auto()


@enum.unique
class Writer(enum.IntFlag):
    """
    c.f. `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html>`__
    """

    _ignore_ = 'Writer _'
    Writer = vars()

    Writer['WRITER_ASCII'] = enum.auto()

    Writer['WRITER_NONE'] = enum.auto()

    Writer['WRITER_SQLITE'] = enum.auto()
