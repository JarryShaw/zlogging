# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Log``."""

from zlogging._compat import enum


@enum.unique
class ID(enum.IntFlag):
    """Enum: ``Log::ID``.

    Type that defines an ID unique to each log stream. Scripts creating new log streams need to redef
    this enum to add their own specific log ID. The log ID implicitly determines the default name of the
    generated log file.

    See Also:
        `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html#type-Log::ID>`__

    """

    _ignore_ = 'ID _'
    ID = vars()

    #: Dummy place-holder.
    UNKNOWN = enum.auto()

    #: Print statements that have been redirected to a log stream.
    PRINTLOG = enum.auto()

    #: Broker::LOG
    #: (present if base/frameworks/broker/log.zeek is loaded)
    Broker_LOG = enum.auto()

    #: Cluster::LOG
    #: (present if base/frameworks/cluster/main.zeek is loaded)
    Cluster_LOG = enum.auto()

    #: Config::LOG
    #: (present if base/frameworks/config/main.zeek is loaded)
    Config_LOG = enum.auto()

    #: DPD::LOG
    #: (present if base/frameworks/analyzer/dpd.zeek is loaded)
    DPD_LOG = enum.auto()

    #: Analyzer::Logging::LOG
    #: (present if base/frameworks/analyzer/logging.zeek is loaded)
    Analyzer_Logging_LOG = enum.auto()

    #: Files::LOG
    #: (present if base/frameworks/files/main.zeek is loaded)
    #: Logging stream for file analysis.
    Files_LOG = enum.auto()

    #: Reporter::LOG
    #: (present if base/frameworks/reporter/main.zeek is loaded)
    Reporter_LOG = enum.auto()

    #: Notice::LOG
    #: (present if base/frameworks/notice/main.zeek is loaded)
    #: This is the primary logging stream for notices.
    Notice_LOG = enum.auto()

    #: Notice::ALARM_LOG
    #: (present if base/frameworks/notice/main.zeek is loaded)
    #: This is the alarm stream.
    Notice_ALARM_LOG = enum.auto()

    #: Weird::LOG
    #: (present if base/frameworks/notice/weird.zeek is loaded)
    Weird_LOG = enum.auto()

    #: Signatures::LOG
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    Signatures_LOG = enum.auto()

    #: PacketFilter::LOG
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    PacketFilter_LOG = enum.auto()

    #: Software::LOG
    #: (present if base/frameworks/software/main.zeek is loaded)
    Software_LOG = enum.auto()

    #: Intel::LOG
    #: (present if base/frameworks/intel/main.zeek is loaded)
    Intel_LOG = enum.auto()

    #: Tunnel::LOG
    #: (present if base/frameworks/tunnels/main.zeek is loaded)
    Tunnel_LOG = enum.auto()

    #: OpenFlow::LOG
    #: (present if base/frameworks/openflow/plugins/log.zeek is loaded)
    OpenFlow_LOG = enum.auto()

    #: NetControl::LOG
    #: (present if base/frameworks/netcontrol/main.zeek is loaded)
    NetControl_LOG = enum.auto()

    #: NetControl::DROP_LOG
    #: (present if base/frameworks/netcontrol/drop.zeek is loaded)
    NetControl_DROP_LOG = enum.auto()

    #: NetControl::SHUNT
    #: (present if base/frameworks/netcontrol/shunt.zeek is loaded)
    NetControl_SHUNT = enum.auto()

    #: Conn::LOG
    #: (present if base/protocols/conn/main.zeek is loaded)
    Conn_LOG = enum.auto()

    #: DCE_RPC::LOG
    #: (present if base/protocols/dce-rpc/main.zeek is loaded)
    DCE_RPC_LOG = enum.auto()

    #: DHCP::LOG
    #: (present if base/protocols/dhcp/main.zeek is loaded)
    DHCP_LOG = enum.auto()

    #: DNP3::LOG
    #: (present if base/protocols/dnp3/main.zeek is loaded)
    DNP3_LOG = enum.auto()

    #: DNS::LOG
    #: (present if base/protocols/dns/main.zeek is loaded)
    DNS_LOG = enum.auto()

    #: FTP::LOG
    #: (present if base/protocols/ftp/main.zeek is loaded)
    FTP_LOG = enum.auto()

    #: SSL::LOG
    #: (present if base/protocols/ssl/main.zeek is loaded)
    SSL_LOG = enum.auto()

    #: X509::LOG
    #: (present if base/files/x509/main.zeek is loaded)
    X509_LOG = enum.auto()

    #: OCSP::LOG
    #: (present if base/files/x509/log-ocsp.zeek is loaded)
    OCSP_LOG = enum.auto()

    #: HTTP::LOG
    #: (present if base/protocols/http/main.zeek is loaded)
    HTTP_LOG = enum.auto()

    #: IRC::LOG
    #: (present if base/protocols/irc/main.zeek is loaded)
    IRC_LOG = enum.auto()

    #: KRB::LOG
    #: (present if base/protocols/krb/main.zeek is loaded)
    KRB_LOG = enum.auto()

    #: LDAP::LDAP_LOG
    #: (present if base/protocols/ldap/main.zeek is loaded)
    LDAP_LDAP_LOG = enum.auto()

    #: LDAP::LDAP_SEARCH_LOG
    #: (present if base/protocols/ldap/main.zeek is loaded)
    LDAP_LDAP_SEARCH_LOG = enum.auto()

    #: Modbus::LOG
    #: (present if base/protocols/modbus/main.zeek is loaded)
    Modbus_LOG = enum.auto()

    #: MQTT::CONNECT_LOG
    #: (present if base/protocols/mqtt/main.zeek is loaded)
    MQTT_CONNECT_LOG = enum.auto()

    #: MQTT::SUBSCRIBE_LOG
    #: (present if base/protocols/mqtt/main.zeek is loaded)
    MQTT_SUBSCRIBE_LOG = enum.auto()

    #: MQTT::PUBLISH_LOG
    #: (present if base/protocols/mqtt/main.zeek is loaded)
    MQTT_PUBLISH_LOG = enum.auto()

    #: mysql::LOG
    #: (present if base/protocols/mysql/main.zeek is loaded)
    mysql_LOG = enum.auto()

    #: NTLM::LOG
    #: (present if base/protocols/ntlm/main.zeek is loaded)
    NTLM_LOG = enum.auto()

    #: NTP::LOG
    #: (present if base/protocols/ntp/main.zeek is loaded)
    NTP_LOG = enum.auto()

    #: QUIC::LOG
    #: (present if base/protocols/quic/main.zeek is loaded)
    QUIC_LOG = enum.auto()

    #: RADIUS::LOG
    #: (present if base/protocols/radius/main.zeek is loaded)
    RADIUS_LOG = enum.auto()

    #: RDP::LOG
    #: (present if base/protocols/rdp/main.zeek is loaded)
    RDP_LOG = enum.auto()

    #: RFB::LOG
    #: (present if base/protocols/rfb/main.zeek is loaded)
    RFB_LOG = enum.auto()

    #: SIP::LOG
    #: (present if base/protocols/sip/main.zeek is loaded)
    SIP_LOG = enum.auto()

    #: SNMP::LOG
    #: (present if base/protocols/snmp/main.zeek is loaded)
    SNMP_LOG = enum.auto()

    #: SMB::MAPPING_LOG
    #: (present if base/protocols/smb/main.zeek is loaded)
    SMB_MAPPING_LOG = enum.auto()

    #: SMB::FILES_LOG
    #: (present if base/protocols/smb/main.zeek is loaded)
    SMB_FILES_LOG = enum.auto()

    #: SMTP::LOG
    #: (present if base/protocols/smtp/main.zeek is loaded)
    SMTP_LOG = enum.auto()

    #: SOCKS::LOG
    #: (present if base/protocols/socks/main.zeek is loaded)
    SOCKS_LOG = enum.auto()

    #: SSH::LOG
    #: (present if base/protocols/ssh/main.zeek is loaded)
    SSH_LOG = enum.auto()

    #: Syslog::LOG
    #: (present if base/protocols/syslog/main.zeek is loaded)
    Syslog_LOG = enum.auto()

    #: WebSocket::LOG
    #: (present if base/protocols/websocket/main.zeek is loaded)
    WebSocket_LOG = enum.auto()

    #: PE::LOG
    #: (present if base/files/pe/main.zeek is loaded)
    PE_LOG = enum.auto()

    #: Management::Log::LOG
    #: (present if policy/frameworks/management/log.zeek is loaded)
    Management_LOG = enum.auto()

    #: NetControl::CATCH_RELEASE
    #: (present if policy/frameworks/netcontrol/catch-and-release.zeek is loaded)
    NetControl_CATCH_RELEASE = enum.auto()

    #: Telemetry::LOG
    #: (present if policy/frameworks/telemetry/log.zeek is loaded)
    Telemetry_LOG = enum.auto()

    #: Telemetry::LOG_HISTOGRAM
    #: (present if policy/frameworks/telemetry/log.zeek is loaded)
    Telemetry_LOG_HISTOGRAM = enum.auto()

    #: CaptureLoss::LOG
    #: (present if policy/misc/capture-loss.zeek is loaded)
    CaptureLoss_LOG = enum.auto()

    #: Traceroute::LOG
    #: (present if policy/misc/detect-traceroute/main.zeek is loaded)
    Traceroute_LOG = enum.auto()

    #: LoadedScripts::LOG
    #: (present if policy/misc/loaded-scripts.zeek is loaded)
    LoadedScripts_LOG = enum.auto()

    #: Stats::LOG
    #: (present if policy/misc/stats.zeek is loaded)
    Stats_LOG = enum.auto()

    #: WeirdStats::LOG
    #: (present if policy/misc/weird-stats.zeek is loaded)
    WeirdStats_LOG = enum.auto()

    #: UnknownProtocol::LOG
    #: (present if policy/misc/unknown-protocols.zeek is loaded)
    UnknownProtocol_LOG = enum.auto()

    #: Known::HOSTS_LOG
    #: (present if policy/protocols/conn/known-hosts.zeek is loaded)
    Known_HOSTS_LOG = enum.auto()

    #: Known::SERVICES_LOG
    #: (present if policy/protocols/conn/known-services.zeek is loaded)
    Known_SERVICES_LOG = enum.auto()

    #: Known::MODBUS_LOG
    #: (present if policy/protocols/modbus/known-masters-slaves.zeek is loaded)
    Known_MODBUS_LOG = enum.auto()

    #: Modbus::REGISTER_CHANGE_LOG
    #: (present if policy/protocols/modbus/track-memmap.zeek is loaded)
    Modbus_REGISTER_CHANGE_LOG = enum.auto()

    #: SMB::CMD_LOG
    #: (present if policy/protocols/smb/log-cmds.zeek is loaded)
    SMB_CMD_LOG = enum.auto()

    #: Known::CERTS_LOG
    #: (present if policy/protocols/ssl/known-certs.zeek is loaded)
    Known_CERTS_LOG = enum.auto()

    #: ZeekygenExample::LOG
    #: (present if zeekygen/example.zeek is loaded)
    ZeekygenExample_LOG = enum.auto()


@enum.unique
class PrintLogType(enum.IntFlag):
    """Enum: ``Log::PrintLogType``.

    Configurations for ``Log::print_to_log``.

    See Also:
        `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html#type-Log::PrintLogType>`__

    """

    _ignore_ = 'PrintLogType _'
    PrintLogType = vars()

    #: No redirection of print statements.
    REDIRECT_NONE = enum.auto()

    #: Redirection of those print statements that were being logged to stdout,
    #: leaving behind those set to go to other specific files.
    REDIRECT_STDOUT = enum.auto()

    #: Redirection of all print statements.
    REDIRECT_ALL = enum.auto()


@enum.unique
class Writer(enum.IntFlag):
    """Enum: ``Log::Writer``.

    See Also:
        `base/frameworks/logging/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/main.zeek.html#type-Log::Writer>`__

    """

    _ignore_ = 'Writer _'
    Writer = vars()

    WRITER_ASCII = enum.auto()

    WRITER_NONE = enum.auto()

    WRITER_SQLITE = enum.auto()
