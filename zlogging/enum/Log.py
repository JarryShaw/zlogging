# -*- coding: utf-8 -*-
"""Namespace: ``Log``."""

from zlogging._compat import enum


@enum.unique
class ID(enum.IntFlag):
    """Type that defines an ID unique to each log stream. Scripts creating new
    log streams need to redef this enum to add their own specific log ID.
    The log ID implicitly determines the default name of the generated log
    file.

    c.f. `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html#type-Log::ID>`__

    """

    _ignore_ = 'ID _'
    ID = vars()

    #: Dummy place-holder.
    ID['UNKNOWN'] = enum.auto()

    #: Print statements that have been redirected to a log stream.
    ID['PRINTLOG'] = enum.auto()

    #: Broker::LOG
    #: (present if base/frameworks/broker/log.zeek is loaded)
    ID['Broker__LOG'] = enum.auto()

    #: Files::LOG
    #: (present if base/frameworks/files/main.zeek is loaded)
    #: Logging stream for file analysis.
    ID['Files__LOG'] = enum.auto()

    #: Reporter::LOG
    #: (present if base/frameworks/reporter/main.zeek is loaded)
    ID['Reporter__LOG'] = enum.auto()

    #: Cluster::LOG
    #: (present if base/frameworks/cluster/main.zeek is loaded)
    ID['Cluster__LOG'] = enum.auto()

    #: Notice::LOG
    #: (present if base/frameworks/notice/main.zeek is loaded)
    #: This is the primary logging stream for notices.
    ID['Notice__LOG'] = enum.auto()

    #: Notice::ALARM_LOG
    #: (present if base/frameworks/notice/main.zeek is loaded)
    #: This is the alarm stream.
    ID['Notice__ALARM_LOG'] = enum.auto()

    #: Weird::LOG
    #: (present if base/frameworks/notice/weird.zeek is loaded)
    ID['Weird__LOG'] = enum.auto()

    #: DPD::LOG
    #: (present if base/frameworks/dpd/main.zeek is loaded)
    ID['DPD__LOG'] = enum.auto()

    #: Signatures::LOG
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    ID['Signatures__LOG'] = enum.auto()

    #: PacketFilter::LOG
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    ID['PacketFilter__LOG'] = enum.auto()

    #: Software::LOG
    #: (present if base/frameworks/software/main.zeek is loaded)
    ID['Software__LOG'] = enum.auto()

    #: Intel::LOG
    #: (present if base/frameworks/intel/main.zeek is loaded)
    ID['Intel__LOG'] = enum.auto()

    #: Config::LOG
    #: (present if base/frameworks/config/main.zeek is loaded)
    ID['Config__LOG'] = enum.auto()

    #: Tunnel::LOG
    #: (present if base/frameworks/tunnels/main.zeek is loaded)
    ID['Tunnel__LOG'] = enum.auto()

    #: OpenFlow::LOG
    #: (present if base/frameworks/openflow/plugins/log.zeek is loaded)
    ID['OpenFlow__LOG'] = enum.auto()

    #: NetControl::LOG
    #: (present if base/frameworks/netcontrol/main.zeek is loaded)
    ID['NetControl__LOG'] = enum.auto()

    #: NetControl::DROP
    #: (present if base/frameworks/netcontrol/types.zeek is loaded)
    #: Stop forwarding all packets matching the entity.
    #: No additional arguments.
    ID['NetControl__DROP'] = enum.auto()

    #: NetControl::SHUNT
    #: (present if base/frameworks/netcontrol/shunt.zeek is loaded)
    ID['NetControl__SHUNT'] = enum.auto()

    #: Conn::LOG
    #: (present if base/protocols/conn/main.zeek is loaded)
    ID['Conn__LOG'] = enum.auto()

    #: DCE_RPC::LOG
    #: (present if base/protocols/dce-rpc/main.zeek is loaded)
    ID['DCE_RPC__LOG'] = enum.auto()

    #: DHCP::LOG
    #: (present if base/protocols/dhcp/main.zeek is loaded)
    ID['DHCP__LOG'] = enum.auto()

    #: DNP3::LOG
    #: (present if base/protocols/dnp3/main.zeek is loaded)
    ID['DNP3__LOG'] = enum.auto()

    #: DNS::LOG
    #: (present if base/protocols/dns/main.zeek is loaded)
    ID['DNS__LOG'] = enum.auto()

    #: FTP::LOG
    #: (present if base/protocols/ftp/main.zeek is loaded)
    ID['FTP__LOG'] = enum.auto()

    #: SSL::LOG
    #: (present if base/protocols/ssl/main.zeek is loaded)
    ID['SSL__LOG'] = enum.auto()

    #: X509::LOG
    #: (present if base/files/x509/main.zeek is loaded)
    ID['X509__LOG'] = enum.auto()

    #: HTTP::LOG
    #: (present if base/protocols/http/main.zeek is loaded)
    ID['HTTP__LOG'] = enum.auto()

    #: IRC::LOG
    #: (present if base/protocols/irc/main.zeek is loaded)
    ID['IRC__LOG'] = enum.auto()

    #: KRB::LOG
    #: (present if base/protocols/krb/main.zeek is loaded)
    ID['KRB__LOG'] = enum.auto()

    #: Modbus::LOG
    #: (present if base/protocols/modbus/main.zeek is loaded)
    ID['Modbus__LOG'] = enum.auto()

    #: mysql::LOG
    #: (present if base/protocols/mysql/main.zeek is loaded)
    ID['mysql__LOG'] = enum.auto()

    #: NTLM::LOG
    #: (present if base/protocols/ntlm/main.zeek is loaded)
    ID['NTLM__LOG'] = enum.auto()

    #: NTP::LOG
    #: (present if base/protocols/ntp/main.zeek is loaded)
    ID['NTP__LOG'] = enum.auto()

    #: RADIUS::LOG
    #: (present if base/protocols/radius/main.zeek is loaded)
    ID['RADIUS__LOG'] = enum.auto()

    #: RDP::LOG
    #: (present if base/protocols/rdp/main.zeek is loaded)
    ID['RDP__LOG'] = enum.auto()

    #: RFB::LOG
    #: (present if base/protocols/rfb/main.zeek is loaded)
    ID['RFB__LOG'] = enum.auto()

    #: SIP::LOG
    #: (present if base/protocols/sip/main.zeek is loaded)
    ID['SIP__LOG'] = enum.auto()

    #: SNMP::LOG
    #: (present if base/protocols/snmp/main.zeek is loaded)
    ID['SNMP__LOG'] = enum.auto()

    #: SMB::AUTH_LOG
    #: (present if base/protocols/smb/main.zeek is loaded)
    ID['SMB__AUTH_LOG'] = enum.auto()

    #: SMB::MAPPING_LOG
    #: (present if base/protocols/smb/main.zeek is loaded)
    ID['SMB__MAPPING_LOG'] = enum.auto()

    #: SMB::FILES_LOG
    #: (present if base/protocols/smb/main.zeek is loaded)
    ID['SMB__FILES_LOG'] = enum.auto()

    #: SMTP::LOG
    #: (present if base/protocols/smtp/main.zeek is loaded)
    ID['SMTP__LOG'] = enum.auto()

    #: SOCKS::LOG
    #: (present if base/protocols/socks/main.zeek is loaded)
    ID['SOCKS__LOG'] = enum.auto()

    #: SSH::LOG
    #: (present if base/protocols/ssh/main.zeek is loaded)
    ID['SSH__LOG'] = enum.auto()

    #: Syslog::LOG
    #: (present if base/protocols/syslog/main.zeek is loaded)
    ID['Syslog__LOG'] = enum.auto()

    #: PE::LOG
    #: (present if base/files/pe/main.zeek is loaded)
    ID['PE__LOG'] = enum.auto()

    #: NetControl::CATCH_RELEASE
    #: (present if policy/frameworks/netcontrol/catch-and-release.zeek is loaded)
    ID['NetControl__CATCH_RELEASE'] = enum.auto()

    #: Unified2::LOG
    #: (present if policy/files/unified2/main.zeek is loaded)
    ID['Unified2__LOG'] = enum.auto()

    #: OCSP::LOG
    #: (present if policy/files/x509/log-ocsp.zeek is loaded)
    ID['OCSP__LOG'] = enum.auto()

    #: Barnyard2::LOG
    #: (present if policy/integration/barnyard2/main.zeek is loaded)
    ID['Barnyard2__LOG'] = enum.auto()

    #: CaptureLoss::LOG
    #: (present if policy/misc/capture-loss.zeek is loaded)
    ID['CaptureLoss__LOG'] = enum.auto()

    #: Traceroute::LOG
    #: (present if policy/misc/detect-traceroute/main.zeek is loaded)
    ID['Traceroute__LOG'] = enum.auto()

    #: LoadedScripts::LOG
    #: (present if policy/misc/loaded-scripts.zeek is loaded)
    ID['LoadedScripts__LOG'] = enum.auto()

    #: Stats::LOG
    #: (present if policy/misc/stats.zeek is loaded)
    ID['Stats__LOG'] = enum.auto()

    #: WeirdStats::LOG
    #: (present if policy/misc/weird-stats.zeek is loaded)
    ID['WeirdStats__LOG'] = enum.auto()

    #: Known::HOSTS_LOG
    #: (present if policy/protocols/conn/known-hosts.zeek is loaded)
    ID['Known__HOSTS_LOG'] = enum.auto()

    #: Known::SERVICES_LOG
    #: (present if policy/protocols/conn/known-services.zeek is loaded)
    ID['Known__SERVICES_LOG'] = enum.auto()

    #: Known::MODBUS_LOG
    #: (present if policy/protocols/modbus/known-masters-slaves.zeek is loaded)
    ID['Known__MODBUS_LOG'] = enum.auto()

    #: Modbus::REGISTER_CHANGE_LOG
    #: (present if policy/protocols/modbus/track-memmap.zeek is loaded)
    ID['Modbus__REGISTER_CHANGE_LOG'] = enum.auto()

    #: MQTT::CONNECT_LOG
    #: (present if policy/protocols/mqtt/main.zeek is loaded)
    ID['MQTT__CONNECT_LOG'] = enum.auto()

    #: MQTT::SUBSCRIBE_LOG
    #: (present if policy/protocols/mqtt/main.zeek is loaded)
    ID['MQTT__SUBSCRIBE_LOG'] = enum.auto()

    #: MQTT::PUBLISH_LOG
    #: (present if policy/protocols/mqtt/main.zeek is loaded)
    ID['MQTT__PUBLISH_LOG'] = enum.auto()

    #: SMB::CMD_LOG
    #: (present if policy/protocols/smb/log-cmds.zeek is loaded)
    ID['SMB__CMD_LOG'] = enum.auto()

    #: Known::CERTS_LOG
    #: (present if policy/protocols/ssl/known-certs.zeek is loaded)
    ID['Known__CERTS_LOG'] = enum.auto()

    #: ZeekygenExample::LOG
    #: (present if zeekygen/example.zeek is loaded)
    ID['ZeekygenExample__LOG'] = enum.auto()


@enum.unique
class PrintLogType(enum.IntFlag):
    """Configurations for Log::print\_to\_log

    c.f. `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html#type-Log::PrintLogType>`__

    """

    _ignore_ = 'PrintLogType _'
    PrintLogType = vars()

    #: No redirection of print statements.
    PrintLogType['REDIRECT_NONE'] = enum.auto()

    #: Redirection of those print statements that were being logged to stdout,
    #: leaving behind those set to go to other specific files.
    PrintLogType['REDIRECT_STDOUT'] = enum.auto()

    #: Redirection of all print statements.
    PrintLogType['REDIRECT_ALL'] = enum.auto()


@enum.unique
class Writer(enum.IntFlag):
    """c.f. `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html#type-Log::Writer>`__"""

    _ignore_ = 'Writer _'
    Writer = vars()

    Writer['WRITER_ASCII'] = enum.auto()

    Writer['WRITER_NONE'] = enum.auto()

    Writer['WRITER_SQLITE'] = enum.auto()
