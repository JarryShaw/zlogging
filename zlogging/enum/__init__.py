# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports,duplicate-key
"""Bro/Zeek enum namespace."""

import builtins
import warnings
from typing import TYPE_CHECKING

from zlogging._exc import BroDeprecationWarning
from zlogging.enum.af_packet import ChecksumMode as AF_Packet_ChecksumMode
from zlogging.enum.af_packet import FanoutMode as AF_Packet_FanoutMode
from zlogging.enum.all_analyzers import Tag as AllAnalyzers_Tag
from zlogging.enum.analyzer import Tag as Analyzer_Tag
from zlogging.enum.asn1 import ASN1Class as ASN1_ASN1Class
from zlogging.enum.asn1 import ASN1Type as ASN1_ASN1Type
from zlogging.enum.broker import BackendType as Broker_BackendType
from zlogging.enum.broker import BrokerProtocol as Broker_BrokerProtocol
from zlogging.enum.broker import DataType as Broker_DataType
from zlogging.enum.broker import ErrorCode as Broker_ErrorCode
from zlogging.enum.broker import PeerStatus as Broker_PeerStatus
from zlogging.enum.broker import QueryStatus as Broker_QueryStatus
from zlogging.enum.broker import SQLiteFailureMode as Broker_SQLiteFailureMode
from zlogging.enum.broker import SQLiteJournalMode as Broker_SQLiteJournalMode
from zlogging.enum.broker import SQLiteSynchronous as Broker_SQLiteSynchronous
from zlogging.enum.broker import Type as Broker_Type
from zlogging.enum.cluster import NodeType as Cluster_NodeType
from zlogging.enum.dce_rpc import IfID as DCE_RPC_IfID
from zlogging.enum.dce_rpc import PType as DCE_RPC_PType
from zlogging.enum.files import Tag as Files_Tag
from zlogging.enum.http import Tags as HTTP_Tags
from zlogging.enum.input import Event as Input_Event
from zlogging.enum.input import Mode as Input_Mode
from zlogging.enum.input import Reader as Input_Reader
from zlogging.enum.intel import Type as Intel_Type
from zlogging.enum.intel import Where as Intel_Where
from zlogging.enum.json import TimestampFormat as JSON_TimestampFormat
from zlogging.enum.known import ModbusDeviceType as Known_ModbusDeviceType
from zlogging.enum.ldap import BindAuthType as LDAP_BindAuthType
from zlogging.enum.ldap import ProtocolOpcode as LDAP_ProtocolOpcode
from zlogging.enum.ldap import ResultCode as LDAP_ResultCode
from zlogging.enum.ldap import SearchDerefAlias as LDAP_SearchDerefAlias
from zlogging.enum.ldap import SearchScope as LDAP_SearchScope
from zlogging.enum.load_balancing import Method as LoadBalancing_Method
from zlogging.enum.log import ID as Log_ID
from zlogging.enum.log import PrintLogType as Log_PrintLogType
from zlogging.enum.log import Writer as Log_Writer
from zlogging.enum.management import Role as Management_Role
from zlogging.enum.management import State as Management_State
from zlogging.enum.management_controller_runtime import \
    ConfigState as Management_Controller_Runtime_ConfigState
from zlogging.enum.management_log import Level as Management_Log_Level
from zlogging.enum.mount3 import auth_flavor_t as MOUNT3_auth_flavor_t
from zlogging.enum.mount3 import proc_t as MOUNT3_proc_t
from zlogging.enum.mount3 import status_t as MOUNT3_status_t
from zlogging.enum.mqtt import SubUnsub as MQTT_SubUnsub
from zlogging.enum.net_control import CatchReleaseActions as NetControl_CatchReleaseActions
from zlogging.enum.net_control import EntityType as NetControl_EntityType
from zlogging.enum.net_control import InfoCategory as NetControl_InfoCategory
from zlogging.enum.net_control import InfoState as NetControl_InfoState
from zlogging.enum.net_control import RuleType as NetControl_RuleType
from zlogging.enum.net_control import TargetType as NetControl_TargetType
from zlogging.enum.nfs3 import createmode_t as NFS3_createmode_t
from zlogging.enum.nfs3 import file_type_t as NFS3_file_type_t
from zlogging.enum.nfs3 import proc_t as NFS3_proc_t
from zlogging.enum.nfs3 import stable_how_t as NFS3_stable_how_t
from zlogging.enum.nfs3 import status_t as NFS3_status_t
from zlogging.enum.nfs3 import time_how_t as NFS3_time_how_t
from zlogging.enum.notice import Action as Notice_Action
from zlogging.enum.notice import Type as Notice_Type
from zlogging.enum.open_flow import Plugin as OpenFlow_Plugin
from zlogging.enum.open_flow import ofp_action_type as OpenFlow_ofp_action_type
from zlogging.enum.open_flow import ofp_config_flags as OpenFlow_ofp_config_flags
from zlogging.enum.open_flow import ofp_flow_mod_command as OpenFlow_ofp_flow_mod_command
from zlogging.enum.packet_analyzer import Tag as PacketAnalyzer_Tag
from zlogging.enum.pcap import filter_state as Pcap_filter_state
from zlogging.enum.protocol_detector import dir as ProtocolDetector_dir
from zlogging.enum.redis import RedisCommand as Redis_RedisCommand
from zlogging.enum.redis import ReplyType as Redis_ReplyType
from zlogging.enum.reporter import Level as Reporter_Level
from zlogging.enum.signatures import Action as Signatures_Action
from zlogging.enum.smb import Action as SMB_Action
from zlogging.enum.socks import RequestType as SOCKS_RequestType
from zlogging.enum.software import Type as Software_Type
from zlogging.enum.spicy import AddressFamily as spicy_AddressFamily
from zlogging.enum.spicy import BitOrder as spicy_BitOrder
from zlogging.enum.spicy import ByteOrder as spicy_ByteOrder
from zlogging.enum.spicy import Charset as spicy_Charset
from zlogging.enum.spicy import DecodeErrorStrategy as spicy_DecodeErrorStrategy
from zlogging.enum.spicy import Direction as spicy_Direction
from zlogging.enum.spicy import Protocol as spicy_Protocol
from zlogging.enum.spicy import RealType as spicy_RealType
from zlogging.enum.spicy import ReassemblerPolicy as spicy_ReassemblerPolicy
from zlogging.enum.spicy import Side as spicy_Side
from zlogging.enum.ssl import SctSource as SSL_SctSource
from zlogging.enum.sum_stats import Calculation as SumStats_Calculation
from zlogging.enum.supervisor import ClusterRole as Supervisor_ClusterRole
from zlogging.enum.telemetry import MetricType as Telemetry_MetricType
from zlogging.enum.tunnel import Action as Tunnel_Action
from zlogging.enum.tunnel import Type as Tunnel_Type
from zlogging.enum.weird import Action as Weird_Action
from zlogging.enum.zeek import Direction as zeek_Direction
from zlogging.enum.zeek import Host as zeek_Host
from zlogging.enum.zeek import IPAddrAnonymization as zeek_IPAddrAnonymization
from zlogging.enum.zeek import IPAddrAnonymizationClass as zeek_IPAddrAnonymizationClass
from zlogging.enum.zeek import PcapFilterID as zeek_PcapFilterID
from zlogging.enum.zeek import TableChange as zeek_TableChange
from zlogging.enum.zeek import layer3_proto as zeek_layer3_proto
from zlogging.enum.zeek import link_encap as zeek_link_encap
from zlogging.enum.zeek import pkt_profile_modes as zeek_pkt_profile_modes
from zlogging.enum.zeek import rpc_status as zeek_rpc_status
from zlogging.enum.zeek import transport_proto as zeek_transport_proto
from zlogging.enum.zeekygen_example import SimpleEnum as ZeekygenExample_SimpleEnum

__all__ = ['globals']

if TYPE_CHECKING:
    from enum import Enum

builtins.globals()['ZLogging::AF_Packet'] = {
    'CHECKSUM_KERNEL': AF_Packet_ChecksumMode.CHECKSUM_KERNEL,
    'CHECKSUM_OFF': AF_Packet_ChecksumMode.CHECKSUM_OFF,
    'CHECKSUM_ON': AF_Packet_ChecksumMode.CHECKSUM_ON,
    'ChecksumMode': AF_Packet_ChecksumMode,
    'FANOUT_CBPF': AF_Packet_FanoutMode.FANOUT_CBPF,
    'FANOUT_CPU': AF_Packet_FanoutMode.FANOUT_CPU,
    'FANOUT_EBPF': AF_Packet_FanoutMode.FANOUT_EBPF,
    'FANOUT_HASH': AF_Packet_FanoutMode.FANOUT_HASH,
    'FANOUT_QM': AF_Packet_FanoutMode.FANOUT_QM,
    'FanoutMode': AF_Packet_FanoutMode,
}

builtins.globals()['ZLogging::ASN1'] = {
    'ASN1Class': ASN1_ASN1Class,
    'ASN1Class_Application': ASN1_ASN1Class.ASN1Class_Application,
    'ASN1Class_ContextSpecific': ASN1_ASN1Class.ASN1Class_ContextSpecific,
    'ASN1Class_Private': ASN1_ASN1Class.ASN1Class_Private,
    'ASN1Class_Undef': ASN1_ASN1Class.ASN1Class_Undef,
    'ASN1Class_Universal': ASN1_ASN1Class.ASN1Class_Universal,
    'ASN1Type': ASN1_ASN1Type,
    'ASN1Type_BMPString': ASN1_ASN1Type.ASN1Type_BMPString,
    'ASN1Type_BitString': ASN1_ASN1Type.ASN1Type_BitString,
    'ASN1Type_Boolean': ASN1_ASN1Type.ASN1Type_Boolean,
    'ASN1Type_CharacterString': ASN1_ASN1Type.ASN1Type_CharacterString,
    'ASN1Type_EmbeddedPDV': ASN1_ASN1Type.ASN1Type_EmbeddedPDV,
    'ASN1Type_Enumerated': ASN1_ASN1Type.ASN1Type_Enumerated,
    'ASN1Type_GeneralString': ASN1_ASN1Type.ASN1Type_GeneralString,
    'ASN1Type_GeneralizedTime': ASN1_ASN1Type.ASN1Type_GeneralizedTime,
    'ASN1Type_GraphicString': ASN1_ASN1Type.ASN1Type_GraphicString,
    'ASN1Type_IA5String': ASN1_ASN1Type.ASN1Type_IA5String,
    'ASN1Type_InstanceOf': ASN1_ASN1Type.ASN1Type_InstanceOf,
    'ASN1Type_Integer': ASN1_ASN1Type.ASN1Type_Integer,
    'ASN1Type_NullVal': ASN1_ASN1Type.ASN1Type_NullVal,
    'ASN1Type_NumericString': ASN1_ASN1Type.ASN1Type_NumericString,
    'ASN1Type_ObjectDescriptor': ASN1_ASN1Type.ASN1Type_ObjectDescriptor,
    'ASN1Type_ObjectIdentifier': ASN1_ASN1Type.ASN1Type_ObjectIdentifier,
    'ASN1Type_OctetString': ASN1_ASN1Type.ASN1Type_OctetString,
    'ASN1Type_PrintableString': ASN1_ASN1Type.ASN1Type_PrintableString,
    'ASN1Type_Real': ASN1_ASN1Type.ASN1Type_Real,
    'ASN1Type_RelativeOID': ASN1_ASN1Type.ASN1Type_RelativeOID,
    'ASN1Type_Sequence': ASN1_ASN1Type.ASN1Type_Sequence,
    'ASN1Type_Set': ASN1_ASN1Type.ASN1Type_Set,
    'ASN1Type_TeletextString': ASN1_ASN1Type.ASN1Type_TeletextString,
    'ASN1Type_UTCTime': ASN1_ASN1Type.ASN1Type_UTCTime,
    'ASN1Type_UTF8String': ASN1_ASN1Type.ASN1Type_UTF8String,
    'ASN1Type_Undef': ASN1_ASN1Type.ASN1Type_Undef,
    'ASN1Type_UniversalString': ASN1_ASN1Type.ASN1Type_UniversalString,
    'ASN1Type_VideotextString': ASN1_ASN1Type.ASN1Type_VideotextString,
    'ASN1Type_VisibleString': ASN1_ASN1Type.ASN1Type_VisibleString,
}

builtins.globals()['ZLogging::AllAnalyzers'] = {
    'ANALYZER_ANALYZER_BITTORRENT': AllAnalyzers_Tag.ANALYZER_ANALYZER_BITTORRENT,
    'ANALYZER_ANALYZER_BITTORRENTTRACKER': AllAnalyzers_Tag.ANALYZER_ANALYZER_BITTORRENTTRACKER,
    'ANALYZER_ANALYZER_CONNSIZE': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONNSIZE,
    'ANALYZER_ANALYZER_CONTENTLINE': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTLINE,
    'ANALYZER_ANALYZER_CONTENTS': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS,
    'ANALYZER_ANALYZER_CONTENTS_DNS': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_DNS,
    'ANALYZER_ANALYZER_CONTENTS_NCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_NCP,
    'ANALYZER_ANALYZER_CONTENTS_NETBIOSSSN': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_NETBIOSSSN,
    'ANALYZER_ANALYZER_CONTENTS_NFS': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_NFS,
    'ANALYZER_ANALYZER_CONTENTS_RLOGIN': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_RLOGIN,
    'ANALYZER_ANALYZER_CONTENTS_RPC': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_RPC,
    'ANALYZER_ANALYZER_CONTENTS_RSH': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_RSH,
    'ANALYZER_ANALYZER_CONTENTS_SMB': AllAnalyzers_Tag.ANALYZER_ANALYZER_CONTENTS_SMB,
    'ANALYZER_ANALYZER_DCE_RPC': AllAnalyzers_Tag.ANALYZER_ANALYZER_DCE_RPC,
    'ANALYZER_ANALYZER_DHCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_DHCP,
    'ANALYZER_ANALYZER_DNP3_TCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_DNP3_TCP,
    'ANALYZER_ANALYZER_DNP3_UDP': AllAnalyzers_Tag.ANALYZER_ANALYZER_DNP3_UDP,
    'ANALYZER_ANALYZER_DNS': AllAnalyzers_Tag.ANALYZER_ANALYZER_DNS,
    'ANALYZER_ANALYZER_DTLS': AllAnalyzers_Tag.ANALYZER_ANALYZER_DTLS,
    'ANALYZER_ANALYZER_FINGER': AllAnalyzers_Tag.ANALYZER_ANALYZER_FINGER,
    'ANALYZER_ANALYZER_FTP': AllAnalyzers_Tag.ANALYZER_ANALYZER_FTP,
    'ANALYZER_ANALYZER_FTP_ADAT': AllAnalyzers_Tag.ANALYZER_ANALYZER_FTP_ADAT,
    'ANALYZER_ANALYZER_FTP_DATA': AllAnalyzers_Tag.ANALYZER_ANALYZER_FTP_DATA,
    'ANALYZER_ANALYZER_GNUTELLA': AllAnalyzers_Tag.ANALYZER_ANALYZER_GNUTELLA,
    'ANALYZER_ANALYZER_GSSAPI': AllAnalyzers_Tag.ANALYZER_ANALYZER_GSSAPI,
    'ANALYZER_ANALYZER_HTTP': AllAnalyzers_Tag.ANALYZER_ANALYZER_HTTP,
    'ANALYZER_ANALYZER_ICMP': AllAnalyzers_Tag.ANALYZER_ANALYZER_ICMP,
    'ANALYZER_ANALYZER_IDENT': AllAnalyzers_Tag.ANALYZER_ANALYZER_IDENT,
    'ANALYZER_ANALYZER_IMAP': AllAnalyzers_Tag.ANALYZER_ANALYZER_IMAP,
    'ANALYZER_ANALYZER_IRC': AllAnalyzers_Tag.ANALYZER_ANALYZER_IRC,
    'ANALYZER_ANALYZER_IRC_DATA': AllAnalyzers_Tag.ANALYZER_ANALYZER_IRC_DATA,
    'ANALYZER_ANALYZER_KRB': AllAnalyzers_Tag.ANALYZER_ANALYZER_KRB,
    'ANALYZER_ANALYZER_KRB_TCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_KRB_TCP,
    'ANALYZER_ANALYZER_LDAP_TCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_LDAP_TCP,
    'ANALYZER_ANALYZER_LDAP_UDP': AllAnalyzers_Tag.ANALYZER_ANALYZER_LDAP_UDP,
    'ANALYZER_ANALYZER_LOGIN': AllAnalyzers_Tag.ANALYZER_ANALYZER_LOGIN,
    'ANALYZER_ANALYZER_MODBUS': AllAnalyzers_Tag.ANALYZER_ANALYZER_MODBUS,
    'ANALYZER_ANALYZER_MOUNT': AllAnalyzers_Tag.ANALYZER_ANALYZER_MOUNT,
    'ANALYZER_ANALYZER_MQTT': AllAnalyzers_Tag.ANALYZER_ANALYZER_MQTT,
    'ANALYZER_ANALYZER_MYSQL': AllAnalyzers_Tag.ANALYZER_ANALYZER_MYSQL,
    'ANALYZER_ANALYZER_NCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_NCP,
    'ANALYZER_ANALYZER_NETBIOSSSN': AllAnalyzers_Tag.ANALYZER_ANALYZER_NETBIOSSSN,
    'ANALYZER_ANALYZER_NFS': AllAnalyzers_Tag.ANALYZER_ANALYZER_NFS,
    'ANALYZER_ANALYZER_NTLM': AllAnalyzers_Tag.ANALYZER_ANALYZER_NTLM,
    'ANALYZER_ANALYZER_NTP': AllAnalyzers_Tag.ANALYZER_ANALYZER_NTP,
    'ANALYZER_ANALYZER_NVT': AllAnalyzers_Tag.ANALYZER_ANALYZER_NVT,
    'ANALYZER_ANALYZER_PIA_TCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_PIA_TCP,
    'ANALYZER_ANALYZER_PIA_UDP': AllAnalyzers_Tag.ANALYZER_ANALYZER_PIA_UDP,
    'ANALYZER_ANALYZER_POP3': AllAnalyzers_Tag.ANALYZER_ANALYZER_POP3,
    'ANALYZER_ANALYZER_PORTMAPPER': AllAnalyzers_Tag.ANALYZER_ANALYZER_PORTMAPPER,
    'ANALYZER_ANALYZER_POSTGRESQL': AllAnalyzers_Tag.ANALYZER_ANALYZER_POSTGRESQL,
    'ANALYZER_ANALYZER_QUIC': AllAnalyzers_Tag.ANALYZER_ANALYZER_QUIC,
    'ANALYZER_ANALYZER_RADIUS': AllAnalyzers_Tag.ANALYZER_ANALYZER_RADIUS,
    'ANALYZER_ANALYZER_RDP': AllAnalyzers_Tag.ANALYZER_ANALYZER_RDP,
    'ANALYZER_ANALYZER_RDPEUDP': AllAnalyzers_Tag.ANALYZER_ANALYZER_RDPEUDP,
    'ANALYZER_ANALYZER_REDIS': AllAnalyzers_Tag.ANALYZER_ANALYZER_REDIS,
    'ANALYZER_ANALYZER_RFB': AllAnalyzers_Tag.ANALYZER_ANALYZER_RFB,
    'ANALYZER_ANALYZER_RLOGIN': AllAnalyzers_Tag.ANALYZER_ANALYZER_RLOGIN,
    'ANALYZER_ANALYZER_RSH': AllAnalyzers_Tag.ANALYZER_ANALYZER_RSH,
    'ANALYZER_ANALYZER_SIP': AllAnalyzers_Tag.ANALYZER_ANALYZER_SIP,
    'ANALYZER_ANALYZER_SMB': AllAnalyzers_Tag.ANALYZER_ANALYZER_SMB,
    'ANALYZER_ANALYZER_SMTP': AllAnalyzers_Tag.ANALYZER_ANALYZER_SMTP,
    'ANALYZER_ANALYZER_SMTP_BDAT': AllAnalyzers_Tag.ANALYZER_ANALYZER_SMTP_BDAT,
    'ANALYZER_ANALYZER_SNMP': AllAnalyzers_Tag.ANALYZER_ANALYZER_SNMP,
    'ANALYZER_ANALYZER_SOCKS': AllAnalyzers_Tag.ANALYZER_ANALYZER_SOCKS,
    'ANALYZER_ANALYZER_SPICY_WEBSOCKET': AllAnalyzers_Tag.ANALYZER_ANALYZER_SPICY_WEBSOCKET,
    'ANALYZER_ANALYZER_SSH': AllAnalyzers_Tag.ANALYZER_ANALYZER_SSH,
    'ANALYZER_ANALYZER_SSL': AllAnalyzers_Tag.ANALYZER_ANALYZER_SSL,
    'ANALYZER_ANALYZER_STREAM_EVENT': AllAnalyzers_Tag.ANALYZER_ANALYZER_STREAM_EVENT,
    'ANALYZER_ANALYZER_SYSLOG': AllAnalyzers_Tag.ANALYZER_ANALYZER_SYSLOG,
    'ANALYZER_ANALYZER_TCP': AllAnalyzers_Tag.ANALYZER_ANALYZER_TCP,
    'ANALYZER_ANALYZER_TCPSTATS': AllAnalyzers_Tag.ANALYZER_ANALYZER_TCPSTATS,
    'ANALYZER_ANALYZER_TELNET': AllAnalyzers_Tag.ANALYZER_ANALYZER_TELNET,
    'ANALYZER_ANALYZER_UDP': AllAnalyzers_Tag.ANALYZER_ANALYZER_UDP,
    'ANALYZER_ANALYZER_UNKNOWN_IP_TRANSPORT': AllAnalyzers_Tag.ANALYZER_ANALYZER_UNKNOWN_IP_TRANSPORT,
    'ANALYZER_ANALYZER_WEBSOCKET': AllAnalyzers_Tag.ANALYZER_ANALYZER_WEBSOCKET,
    'ANALYZER_ANALYZER_XMPP': AllAnalyzers_Tag.ANALYZER_ANALYZER_XMPP,
    'ANALYZER_ANALYZER_ZIP': AllAnalyzers_Tag.ANALYZER_ANALYZER_ZIP,
    'FILES_ANALYZER_DATA_EVENT': AllAnalyzers_Tag.FILES_ANALYZER_DATA_EVENT,
    'FILES_ANALYZER_ENTROPY': AllAnalyzers_Tag.FILES_ANALYZER_ENTROPY,
    'FILES_ANALYZER_EXTRACT': AllAnalyzers_Tag.FILES_ANALYZER_EXTRACT,
    'FILES_ANALYZER_MD5': AllAnalyzers_Tag.FILES_ANALYZER_MD5,
    'FILES_ANALYZER_OCSP_REPLY': AllAnalyzers_Tag.FILES_ANALYZER_OCSP_REPLY,
    'FILES_ANALYZER_OCSP_REQUEST': AllAnalyzers_Tag.FILES_ANALYZER_OCSP_REQUEST,
    'FILES_ANALYZER_PE': AllAnalyzers_Tag.FILES_ANALYZER_PE,
    'FILES_ANALYZER_SHA1': AllAnalyzers_Tag.FILES_ANALYZER_SHA1,
    'FILES_ANALYZER_SHA224': AllAnalyzers_Tag.FILES_ANALYZER_SHA224,
    'FILES_ANALYZER_SHA256': AllAnalyzers_Tag.FILES_ANALYZER_SHA256,
    'FILES_ANALYZER_SHA384': AllAnalyzers_Tag.FILES_ANALYZER_SHA384,
    'FILES_ANALYZER_SHA512': AllAnalyzers_Tag.FILES_ANALYZER_SHA512,
    'FILES_ANALYZER_X509': AllAnalyzers_Tag.FILES_ANALYZER_X509,
    'PACKETANALYZER_ANALYZER_ARP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_ARP,
    'PACKETANALYZER_ANALYZER_AYIYA': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_AYIYA,
    'PACKETANALYZER_ANALYZER_ETHERNET': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_ETHERNET,
    'PACKETANALYZER_ANALYZER_FDDI': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_FDDI,
    'PACKETANALYZER_ANALYZER_GENEVE': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_GENEVE,
    'PACKETANALYZER_ANALYZER_GRE': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_GRE,
    'PACKETANALYZER_ANALYZER_GTPV1': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_GTPV1,
    'PACKETANALYZER_ANALYZER_ICMP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_ICMP,
    'PACKETANALYZER_ANALYZER_IEEE802_11': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_IEEE802_11,
    'PACKETANALYZER_ANALYZER_IEEE802_11_RADIO': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_IEEE802_11_RADIO,
    'PACKETANALYZER_ANALYZER_IGMP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_IGMP,
    'PACKETANALYZER_ANALYZER_IP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_IP,
    'PACKETANALYZER_ANALYZER_IPTUNNEL': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_IPTUNNEL,
    'PACKETANALYZER_ANALYZER_LINUXSLL': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_LINUXSLL,
    'PACKETANALYZER_ANALYZER_LINUXSLL2': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_LINUXSLL2,
    'PACKETANALYZER_ANALYZER_LLC': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_LLC,
    'PACKETANALYZER_ANALYZER_MPLS': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_MPLS,
    'PACKETANALYZER_ANALYZER_NFLOG': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_NFLOG,
    'PACKETANALYZER_ANALYZER_NOVELL_802_3': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_NOVELL_802_3,
    'PACKETANALYZER_ANALYZER_NULL': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_NULL,
    'PACKETANALYZER_ANALYZER_PBB': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_PBB,
    'PACKETANALYZER_ANALYZER_PPP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_PPP,
    'PACKETANALYZER_ANALYZER_PPPOE': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_PPPOE,
    'PACKETANALYZER_ANALYZER_PPPSERIAL': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_PPPSERIAL,
    'PACKETANALYZER_ANALYZER_ROOT': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_ROOT,
    'PACKETANALYZER_ANALYZER_SKIP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_SKIP,
    'PACKETANALYZER_ANALYZER_SNAP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_SNAP,
    'PACKETANALYZER_ANALYZER_TCP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_TCP,
    'PACKETANALYZER_ANALYZER_TEREDO': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_TEREDO,
    'PACKETANALYZER_ANALYZER_UDP': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_UDP,
    'PACKETANALYZER_ANALYZER_UNKNOWN_IP_TRANSPORT': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_UNKNOWN_IP_TRANSPORT,
    'PACKETANALYZER_ANALYZER_VLAN': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_VLAN,
    'PACKETANALYZER_ANALYZER_VNTAG': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_VNTAG,
    'PACKETANALYZER_ANALYZER_VXLAN': AllAnalyzers_Tag.PACKETANALYZER_ANALYZER_VXLAN,
    'Tag': AllAnalyzers_Tag,
}

builtins.globals()['ZLogging::Analyzer'] = {
    'ANALYZER_BITTORRENT': Analyzer_Tag.ANALYZER_BITTORRENT,
    'ANALYZER_BITTORRENTTRACKER': Analyzer_Tag.ANALYZER_BITTORRENTTRACKER,
    'ANALYZER_CONNSIZE': Analyzer_Tag.ANALYZER_CONNSIZE,
    'ANALYZER_CONTENTLINE': Analyzer_Tag.ANALYZER_CONTENTLINE,
    'ANALYZER_CONTENTS': Analyzer_Tag.ANALYZER_CONTENTS,
    'ANALYZER_CONTENTS_DNS': Analyzer_Tag.ANALYZER_CONTENTS_DNS,
    'ANALYZER_CONTENTS_NCP': Analyzer_Tag.ANALYZER_CONTENTS_NCP,
    'ANALYZER_CONTENTS_NETBIOSSSN': Analyzer_Tag.ANALYZER_CONTENTS_NETBIOSSSN,
    'ANALYZER_CONTENTS_NFS': Analyzer_Tag.ANALYZER_CONTENTS_NFS,
    'ANALYZER_CONTENTS_RLOGIN': Analyzer_Tag.ANALYZER_CONTENTS_RLOGIN,
    'ANALYZER_CONTENTS_RPC': Analyzer_Tag.ANALYZER_CONTENTS_RPC,
    'ANALYZER_CONTENTS_RSH': Analyzer_Tag.ANALYZER_CONTENTS_RSH,
    'ANALYZER_CONTENTS_SMB': Analyzer_Tag.ANALYZER_CONTENTS_SMB,
    'ANALYZER_DCE_RPC': Analyzer_Tag.ANALYZER_DCE_RPC,
    'ANALYZER_DHCP': Analyzer_Tag.ANALYZER_DHCP,
    'ANALYZER_DNP3_TCP': Analyzer_Tag.ANALYZER_DNP3_TCP,
    'ANALYZER_DNP3_UDP': Analyzer_Tag.ANALYZER_DNP3_UDP,
    'ANALYZER_DNS': Analyzer_Tag.ANALYZER_DNS,
    'ANALYZER_DTLS': Analyzer_Tag.ANALYZER_DTLS,
    'ANALYZER_FINGER': Analyzer_Tag.ANALYZER_FINGER,
    'ANALYZER_FTP': Analyzer_Tag.ANALYZER_FTP,
    'ANALYZER_FTP_ADAT': Analyzer_Tag.ANALYZER_FTP_ADAT,
    'ANALYZER_FTP_DATA': Analyzer_Tag.ANALYZER_FTP_DATA,
    'ANALYZER_GNUTELLA': Analyzer_Tag.ANALYZER_GNUTELLA,
    'ANALYZER_GSSAPI': Analyzer_Tag.ANALYZER_GSSAPI,
    'ANALYZER_HTTP': Analyzer_Tag.ANALYZER_HTTP,
    'ANALYZER_ICMP': Analyzer_Tag.ANALYZER_ICMP,
    'ANALYZER_IDENT': Analyzer_Tag.ANALYZER_IDENT,
    'ANALYZER_IMAP': Analyzer_Tag.ANALYZER_IMAP,
    'ANALYZER_IRC': Analyzer_Tag.ANALYZER_IRC,
    'ANALYZER_IRC_DATA': Analyzer_Tag.ANALYZER_IRC_DATA,
    'ANALYZER_KRB': Analyzer_Tag.ANALYZER_KRB,
    'ANALYZER_KRB_TCP': Analyzer_Tag.ANALYZER_KRB_TCP,
    'ANALYZER_LDAP_TCP': Analyzer_Tag.ANALYZER_LDAP_TCP,
    'ANALYZER_LDAP_UDP': Analyzer_Tag.ANALYZER_LDAP_UDP,
    'ANALYZER_LOGIN': Analyzer_Tag.ANALYZER_LOGIN,
    'ANALYZER_MODBUS': Analyzer_Tag.ANALYZER_MODBUS,
    'ANALYZER_MOUNT': Analyzer_Tag.ANALYZER_MOUNT,
    'ANALYZER_MQTT': Analyzer_Tag.ANALYZER_MQTT,
    'ANALYZER_MYSQL': Analyzer_Tag.ANALYZER_MYSQL,
    'ANALYZER_NCP': Analyzer_Tag.ANALYZER_NCP,
    'ANALYZER_NETBIOSSSN': Analyzer_Tag.ANALYZER_NETBIOSSSN,
    'ANALYZER_NFS': Analyzer_Tag.ANALYZER_NFS,
    'ANALYZER_NTLM': Analyzer_Tag.ANALYZER_NTLM,
    'ANALYZER_NTP': Analyzer_Tag.ANALYZER_NTP,
    'ANALYZER_NVT': Analyzer_Tag.ANALYZER_NVT,
    'ANALYZER_PIA_TCP': Analyzer_Tag.ANALYZER_PIA_TCP,
    'ANALYZER_PIA_UDP': Analyzer_Tag.ANALYZER_PIA_UDP,
    'ANALYZER_POP3': Analyzer_Tag.ANALYZER_POP3,
    'ANALYZER_PORTMAPPER': Analyzer_Tag.ANALYZER_PORTMAPPER,
    'ANALYZER_POSTGRESQL': Analyzer_Tag.ANALYZER_POSTGRESQL,
    'ANALYZER_QUIC': Analyzer_Tag.ANALYZER_QUIC,
    'ANALYZER_RADIUS': Analyzer_Tag.ANALYZER_RADIUS,
    'ANALYZER_RDP': Analyzer_Tag.ANALYZER_RDP,
    'ANALYZER_RDPEUDP': Analyzer_Tag.ANALYZER_RDPEUDP,
    'ANALYZER_REDIS': Analyzer_Tag.ANALYZER_REDIS,
    'ANALYZER_RFB': Analyzer_Tag.ANALYZER_RFB,
    'ANALYZER_RLOGIN': Analyzer_Tag.ANALYZER_RLOGIN,
    'ANALYZER_RSH': Analyzer_Tag.ANALYZER_RSH,
    'ANALYZER_SIP': Analyzer_Tag.ANALYZER_SIP,
    'ANALYZER_SMB': Analyzer_Tag.ANALYZER_SMB,
    'ANALYZER_SMTP': Analyzer_Tag.ANALYZER_SMTP,
    'ANALYZER_SMTP_BDAT': Analyzer_Tag.ANALYZER_SMTP_BDAT,
    'ANALYZER_SNMP': Analyzer_Tag.ANALYZER_SNMP,
    'ANALYZER_SOCKS': Analyzer_Tag.ANALYZER_SOCKS,
    'ANALYZER_SPICY_WEBSOCKET': Analyzer_Tag.ANALYZER_SPICY_WEBSOCKET,
    'ANALYZER_SSH': Analyzer_Tag.ANALYZER_SSH,
    'ANALYZER_SSL': Analyzer_Tag.ANALYZER_SSL,
    'ANALYZER_STREAM_EVENT': Analyzer_Tag.ANALYZER_STREAM_EVENT,
    'ANALYZER_SYSLOG': Analyzer_Tag.ANALYZER_SYSLOG,
    'ANALYZER_TCP': Analyzer_Tag.ANALYZER_TCP,
    'ANALYZER_TCPSTATS': Analyzer_Tag.ANALYZER_TCPSTATS,
    'ANALYZER_TELNET': Analyzer_Tag.ANALYZER_TELNET,
    'ANALYZER_UDP': Analyzer_Tag.ANALYZER_UDP,
    'ANALYZER_UNKNOWN_IP_TRANSPORT': Analyzer_Tag.ANALYZER_UNKNOWN_IP_TRANSPORT,
    'ANALYZER_WEBSOCKET': Analyzer_Tag.ANALYZER_WEBSOCKET,
    'ANALYZER_XMPP': Analyzer_Tag.ANALYZER_XMPP,
    'ANALYZER_ZIP': Analyzer_Tag.ANALYZER_ZIP,
    'Tag': Analyzer_Tag,
}

builtins.globals()['ZLogging::Analyzer::Logging'] = {
    'Analyzer_Logging_LOG': Log_ID.Analyzer_Logging_LOG,
}

builtins.globals()['ZLogging::Broker'] = {
    'ADDR': Broker_DataType.ADDR,
    'BACKEND_FAILURE': Broker_ErrorCode.BACKEND_FAILURE,
    'BOOL': Broker_DataType.BOOL,
    'BackendType': Broker_BackendType,
    'BrokerProtocol': Broker_BrokerProtocol,
    'Broker_LOG': Log_ID.Broker_LOG,
    'CAF_ERROR': Broker_ErrorCode.CAF_ERROR,
    'CANNOT_OPEN_FILE': Broker_ErrorCode.CANNOT_OPEN_FILE,
    'CANNOT_WRITE_FILE': Broker_ErrorCode.CANNOT_WRITE_FILE,
    'CONNECTED': Broker_PeerStatus.CONNECTED,
    'CONNECTING': Broker_PeerStatus.CONNECTING,
    'COUNT': Broker_DataType.COUNT,
    'DISCONNECTED': Broker_PeerStatus.DISCONNECTED,
    'DOUBLE': Broker_DataType.DOUBLE,
    'DataType': Broker_DataType,
    'END_OF_FILE': Broker_ErrorCode.END_OF_FILE,
    'ENUM': Broker_DataType.ENUM,
    'ERROR': Broker_Type.ERROR,
    'ErrorCode': Broker_ErrorCode,
    'FAILURE': Broker_QueryStatus.FAILURE,
    'INITIALIZING': Broker_PeerStatus.INITIALIZING,
    'INT': Broker_DataType.INT,
    'INTERVAL': Broker_DataType.INTERVAL,
    'INVALID_DATA': Broker_ErrorCode.INVALID_DATA,
    'INVALID_STATUS': Broker_ErrorCode.INVALID_STATUS,
    'INVALID_TAG': Broker_ErrorCode.INVALID_TAG,
    'INVALID_TOPIC_KEY': Broker_ErrorCode.INVALID_TOPIC_KEY,
    'MASTER_EXISTS': Broker_ErrorCode.MASTER_EXISTS,
    'MEMORY': Broker_BackendType.MEMORY,
    'NATIVE': Broker_BrokerProtocol.NATIVE,
    'NONE': Broker_DataType.NONE,
    'NO_ERROR': Broker_ErrorCode.NO_ERROR,
    'NO_SUCH_KEY': Broker_ErrorCode.NO_SUCH_KEY,
    'NO_SUCH_MASTER': Broker_ErrorCode.NO_SUCH_MASTER,
    'PEERED': Broker_PeerStatus.PEERED,
    'PEER_DISCONNECT_DURING_HANDSHAKE': Broker_ErrorCode.PEER_DISCONNECT_DURING_HANDSHAKE,
    'PEER_INCOMPATIBLE': Broker_ErrorCode.PEER_INCOMPATIBLE,
    'PEER_INVALID': Broker_ErrorCode.PEER_INVALID,
    'PEER_TIMEOUT': Broker_ErrorCode.PEER_TIMEOUT,
    'PEER_UNAVAILABLE': Broker_ErrorCode.PEER_UNAVAILABLE,
    'PORT': Broker_DataType.PORT,
    'PeerStatus': Broker_PeerStatus,
    'QueryStatus': Broker_QueryStatus,
    'RECONNECTING': Broker_PeerStatus.RECONNECTING,
    'REQUEST_TIMEOUT': Broker_ErrorCode.REQUEST_TIMEOUT,
    'SET': Broker_DataType.SET,
    'SQLITE': Broker_BackendType.SQLITE,
    'SQLITE_FAILURE_MODE_DELETE': Broker_SQLiteFailureMode.SQLITE_FAILURE_MODE_DELETE,
    'SQLITE_FAILURE_MODE_FAIL': Broker_SQLiteFailureMode.SQLITE_FAILURE_MODE_FAIL,
    'SQLITE_JOURNAL_MODE_DELETE': Broker_SQLiteJournalMode.SQLITE_JOURNAL_MODE_DELETE,
    'SQLITE_JOURNAL_MODE_WAL': Broker_SQLiteJournalMode.SQLITE_JOURNAL_MODE_WAL,
    'SQLITE_SYNCHRONOUS_EXTRA': Broker_SQLiteSynchronous.SQLITE_SYNCHRONOUS_EXTRA,
    'SQLITE_SYNCHRONOUS_FULL': Broker_SQLiteSynchronous.SQLITE_SYNCHRONOUS_FULL,
    'SQLITE_SYNCHRONOUS_NORMAL': Broker_SQLiteSynchronous.SQLITE_SYNCHRONOUS_NORMAL,
    'SQLITE_SYNCHRONOUS_OFF': Broker_SQLiteSynchronous.SQLITE_SYNCHRONOUS_OFF,
    'SQLiteFailureMode': Broker_SQLiteFailureMode,
    'SQLiteJournalMode': Broker_SQLiteJournalMode,
    'SQLiteSynchronous': Broker_SQLiteSynchronous,
    'STALE_DATA': Broker_ErrorCode.STALE_DATA,
    'STATUS': Broker_Type.STATUS,
    'STRING': Broker_DataType.STRING,
    'SUBNET': Broker_DataType.SUBNET,
    'SUCCESS': Broker_QueryStatus.SUCCESS,
    'TABLE': Broker_DataType.TABLE,
    'TIME': Broker_DataType.TIME,
    'TYPE_CLASH': Broker_ErrorCode.TYPE_CLASH,
    'Type': Broker_Type,
    'UNSPECIFIED': Broker_ErrorCode.UNSPECIFIED,
    'VECTOR': Broker_DataType.VECTOR,
    'WEBSOCKET': Broker_BrokerProtocol.WEBSOCKET,
}

builtins.globals()['ZLogging::CaptureLoss'] = {
    'CaptureLoss_LOG': Log_ID.CaptureLoss_LOG,
    'CaptureLoss_Too_Little_Traffic': Notice_Type.CaptureLoss_Too_Little_Traffic,
    'CaptureLoss_Too_Much_Loss': Notice_Type.CaptureLoss_Too_Much_Loss,
}

builtins.globals()['ZLogging::Cluster'] = {
    'CONTROL': Cluster_NodeType.CONTROL,
    'Cluster_LOG': Log_ID.Cluster_LOG,
    'LOGGER': Cluster_NodeType.LOGGER,
    'MANAGER': Cluster_NodeType.MANAGER,
    'NONE': Cluster_NodeType.NONE,
    'NodeType': Cluster_NodeType,
    'PROXY': Cluster_NodeType.PROXY,
    'TIME_MACHINE': Cluster_NodeType.TIME_MACHINE,
    'WORKER': Cluster_NodeType.WORKER,
}

builtins.globals()['ZLogging::Config'] = {
    'Config_LOG': Log_ID.Config_LOG,
}

builtins.globals()['ZLogging::Conn'] = {
    'Conn_Content_Gap': Notice_Type.Conn_Content_Gap,
    'Conn_IN_ORIG': Intel_Where.Conn_IN_ORIG,
    'Conn_IN_RESP': Intel_Where.Conn_IN_RESP,
    'Conn_LOG': Log_ID.Conn_LOG,
    'Conn_Retransmission_Inconsistency': Notice_Type.Conn_Retransmission_Inconsistency,
}

builtins.globals()['ZLogging::DCE_RPC'] = {
    'ACK': DCE_RPC_PType.ACK,
    'ACK': DCE_RPC_PType.ACK,
    'ALTER_CONTEXT': DCE_RPC_PType.ALTER_CONTEXT,
    'ALTER_CONTEXT': DCE_RPC_PType.ALTER_CONTEXT,
    'ALTER_CONTEXT_RESP': DCE_RPC_PType.ALTER_CONTEXT_RESP,
    'ALTER_CONTEXT_RESP': DCE_RPC_PType.ALTER_CONTEXT_RESP,
    'AUTH3': DCE_RPC_PType.AUTH3,
    'AUTH3': DCE_RPC_PType.AUTH3,
    'BIND': DCE_RPC_PType.BIND,
    'BIND': DCE_RPC_PType.BIND,
    'BIND_ACK': DCE_RPC_PType.BIND_ACK,
    'BIND_ACK': DCE_RPC_PType.BIND_ACK,
    'BIND_NAK': DCE_RPC_PType.BIND_NAK,
    'BIND_NAK': DCE_RPC_PType.BIND_NAK,
    'CANCEL_ACK': DCE_RPC_PType.CANCEL_ACK,
    'CANCEL_ACK': DCE_RPC_PType.CANCEL_ACK,
    'CL_CANCEL': DCE_RPC_PType.CL_CANCEL,
    'CL_CANCEL': DCE_RPC_PType.CL_CANCEL,
    'CO_CANCEL': DCE_RPC_PType.CO_CANCEL,
    'CO_CANCEL': DCE_RPC_PType.CO_CANCEL,
    'DCE_RPC_LOG': Log_ID.DCE_RPC_LOG,
    'FACK': DCE_RPC_PType.FACK,
    'FACK': DCE_RPC_PType.FACK,
    'FAULT': DCE_RPC_PType.FAULT,
    'FAULT': DCE_RPC_PType.FAULT,
    'ISCMActivator': DCE_RPC_IfID.ISCMActivator,
    'ISCMActivator': DCE_RPC_IfID.ISCMActivator,
    'IfID': DCE_RPC_IfID,
    'NOCALL': DCE_RPC_PType.NOCALL,
    'NOCALL': DCE_RPC_PType.NOCALL,
    'ORPHANED': DCE_RPC_PType.ORPHANED,
    'ORPHANED': DCE_RPC_PType.ORPHANED,
    'PING': DCE_RPC_PType.PING,
    'PING': DCE_RPC_PType.PING,
    'PType': DCE_RPC_PType,
    'REJECT': DCE_RPC_PType.REJECT,
    'REJECT': DCE_RPC_PType.REJECT,
    'REQUEST': DCE_RPC_PType.REQUEST,
    'REQUEST': DCE_RPC_PType.REQUEST,
    'RESPONSE': DCE_RPC_PType.RESPONSE,
    'RESPONSE': DCE_RPC_PType.RESPONSE,
    'RTS': DCE_RPC_PType.RTS,
    'RTS': DCE_RPC_PType.RTS,
    'SHUTDOWN': DCE_RPC_PType.SHUTDOWN,
    'SHUTDOWN': DCE_RPC_PType.SHUTDOWN,
    'WORKING': DCE_RPC_PType.WORKING,
    'WORKING': DCE_RPC_PType.WORKING,
    'drs': DCE_RPC_IfID.drs,
    'drs': DCE_RPC_IfID.drs,
    'epmapper': DCE_RPC_IfID.epmapper,
    'epmapper': DCE_RPC_IfID.epmapper,
    'lsa_ds': DCE_RPC_IfID.lsa_ds,
    'lsa_ds': DCE_RPC_IfID.lsa_ds,
    'lsarpc': DCE_RPC_IfID.lsarpc,
    'lsarpc': DCE_RPC_IfID.lsarpc,
    'mgmt': DCE_RPC_IfID.mgmt,
    'mgmt': DCE_RPC_IfID.mgmt,
    'netlogon': DCE_RPC_IfID.netlogon,
    'netlogon': DCE_RPC_IfID.netlogon,
    'oxid': DCE_RPC_IfID.oxid,
    'oxid': DCE_RPC_IfID.oxid,
    'samr': DCE_RPC_IfID.samr,
    'samr': DCE_RPC_IfID.samr,
    'spoolss': DCE_RPC_IfID.spoolss,
    'spoolss': DCE_RPC_IfID.spoolss,
    'srvsvc': DCE_RPC_IfID.srvsvc,
    'srvsvc': DCE_RPC_IfID.srvsvc,
    'unknown_if': DCE_RPC_IfID.unknown_if,
    'unknown_if': DCE_RPC_IfID.unknown_if,
    'winspipe': DCE_RPC_IfID.winspipe,
    'winspipe': DCE_RPC_IfID.winspipe,
    'wkssvc': DCE_RPC_IfID.wkssvc,
    'wkssvc': DCE_RPC_IfID.wkssvc,
}

builtins.globals()['ZLogging::DHCP'] = {
    'DHCP_CLIENT': Software_Type.DHCP_CLIENT,
    'DHCP_LOG': Log_ID.DHCP_LOG,
    'DHCP_SERVER': Software_Type.DHCP_SERVER,
}

builtins.globals()['ZLogging::DNP3'] = {
    'DNP3_LOG': Log_ID.DNP3_LOG,
}

builtins.globals()['ZLogging::DNS'] = {
    'DNS_External_Name': Notice_Type.DNS_External_Name,
    'DNS_IN_REQUEST': Intel_Where.DNS_IN_REQUEST,
    'DNS_IN_RESPONSE': Intel_Where.DNS_IN_RESPONSE,
    'DNS_LOG': Log_ID.DNS_LOG,
}

builtins.globals()['ZLogging::DPD'] = {
    'DPD_LOG': Log_ID.DPD_LOG,
}

builtins.globals()['ZLogging::FTP'] = {
    'FTP_Bruteforcing': Notice_Type.FTP_Bruteforcing,
    'FTP_CLIENT': Software_Type.FTP_CLIENT,
    'FTP_LOG': Log_ID.FTP_LOG,
    'FTP_SERVER': Software_Type.FTP_SERVER,
    'FTP_Site_Exec_Success': Notice_Type.FTP_Site_Exec_Success,
}

builtins.globals()['ZLogging::Files'] = {
    'ANALYZER_DATA_EVENT': Files_Tag.ANALYZER_DATA_EVENT,
    'ANALYZER_ENTROPY': Files_Tag.ANALYZER_ENTROPY,
    'ANALYZER_EXTRACT': Files_Tag.ANALYZER_EXTRACT,
    'ANALYZER_MD5': Files_Tag.ANALYZER_MD5,
    'ANALYZER_OCSP_REPLY': Files_Tag.ANALYZER_OCSP_REPLY,
    'ANALYZER_OCSP_REQUEST': Files_Tag.ANALYZER_OCSP_REQUEST,
    'ANALYZER_PE': Files_Tag.ANALYZER_PE,
    'ANALYZER_SHA1': Files_Tag.ANALYZER_SHA1,
    'ANALYZER_SHA224': Files_Tag.ANALYZER_SHA224,
    'ANALYZER_SHA256': Files_Tag.ANALYZER_SHA256,
    'ANALYZER_SHA384': Files_Tag.ANALYZER_SHA384,
    'ANALYZER_SHA512': Files_Tag.ANALYZER_SHA512,
    'ANALYZER_X509': Files_Tag.ANALYZER_X509,
    'Files_IN_HASH': Intel_Where.Files_IN_HASH,
    'Files_IN_NAME': Intel_Where.Files_IN_NAME,
    'Files_LOG': Log_ID.Files_LOG,
    'Tag': Files_Tag,
}

builtins.globals()['ZLogging::HTTP'] = {
    'COOKIE_SQLI': HTTP_Tags.COOKIE_SQLI,
    'EMPTY': HTTP_Tags.EMPTY,
    'HTTP_APPSERVER': Software_Type.HTTP_APPSERVER,
    'HTTP_BROWSER': Software_Type.HTTP_BROWSER,
    'HTTP_BROWSER_PLUGIN': Software_Type.HTTP_BROWSER_PLUGIN,
    'HTTP_IN_HOST_HEADER': Intel_Where.HTTP_IN_HOST_HEADER,
    'HTTP_IN_REFERRER_HEADER': Intel_Where.HTTP_IN_REFERRER_HEADER,
    'HTTP_IN_URL': Intel_Where.HTTP_IN_URL,
    'HTTP_IN_USER_AGENT_HEADER': Intel_Where.HTTP_IN_USER_AGENT_HEADER,
    'HTTP_IN_X_FORWARDED_FOR_HEADER': Intel_Where.HTTP_IN_X_FORWARDED_FOR_HEADER,
    'HTTP_LOG': Log_ID.HTTP_LOG,
    'HTTP_SERVER': Software_Type.HTTP_SERVER,
    'HTTP_SQL_Injection_Attacker': Notice_Type.HTTP_SQL_Injection_Attacker,
    'HTTP_SQL_Injection_Victim': Notice_Type.HTTP_SQL_Injection_Victim,
    'HTTP_WEB_APPLICATION': Software_Type.HTTP_WEB_APPLICATION,
    'POST_SQLI': HTTP_Tags.POST_SQLI,
    'Tags': HTTP_Tags,
    'URI_SQLI': HTTP_Tags.URI_SQLI,
}

builtins.globals()['ZLogging::Heartbleed'] = {
    'Heartbleed_SSL_Heartbeat_Attack': Notice_Type.Heartbleed_SSL_Heartbeat_Attack,
    'Heartbleed_SSL_Heartbeat_Attack_Success': Notice_Type.Heartbleed_SSL_Heartbeat_Attack_Success,
    'Heartbleed_SSL_Heartbeat_Many_Requests': Notice_Type.Heartbleed_SSL_Heartbeat_Many_Requests,
    'Heartbleed_SSL_Heartbeat_Odd_Length': Notice_Type.Heartbleed_SSL_Heartbeat_Odd_Length,
}

builtins.globals()['ZLogging::IRC'] = {
    'IRC_LOG': Log_ID.IRC_LOG,
}

builtins.globals()['ZLogging::Input'] = {
    'EVENT_CHANGED': Input_Event.EVENT_CHANGED,
    'EVENT_NEW': Input_Event.EVENT_NEW,
    'EVENT_REMOVED': Input_Event.EVENT_REMOVED,
    'Event': Input_Event,
    'MANUAL': Input_Mode.MANUAL,
    'Mode': Input_Mode,
    'READER_ASCII': Input_Reader.READER_ASCII,
    'READER_BENCHMARK': Input_Reader.READER_BENCHMARK,
    'READER_BINARY': Input_Reader.READER_BINARY,
    'READER_CONFIG': Input_Reader.READER_CONFIG,
    'READER_RAW': Input_Reader.READER_RAW,
    'READER_SQLITE': Input_Reader.READER_SQLITE,
    'REREAD': Input_Mode.REREAD,
    'Reader': Input_Reader,
    'STREAM': Input_Mode.STREAM,
}

builtins.globals()['ZLogging::Intel'] = {
    'ADDR': Intel_Type.ADDR,
    'CERT_HASH': Intel_Type.CERT_HASH,
    'DOMAIN': Intel_Type.DOMAIN,
    'EMAIL': Intel_Type.EMAIL,
    'FILE_HASH': Intel_Type.FILE_HASH,
    'FILE_NAME': Intel_Type.FILE_NAME,
    'IN_ANYWHERE': Intel_Where.IN_ANYWHERE,
    'Intel_LOG': Log_ID.Intel_LOG,
    'Intel_Notice': Notice_Type.Intel_Notice,
    'PUBKEY_HASH': Intel_Type.PUBKEY_HASH,
    'SOFTWARE': Intel_Type.SOFTWARE,
    'SUBNET': Intel_Type.SUBNET,
    'Type': Intel_Type,
    'URL': Intel_Type.URL,
    'USER_NAME': Intel_Type.USER_NAME,
    'Where': Intel_Where,
}

builtins.globals()['ZLogging::JSON'] = {
    'TS_EPOCH': JSON_TimestampFormat.TS_EPOCH,
    'TS_ISO8601': JSON_TimestampFormat.TS_ISO8601,
    'TS_MILLIS': JSON_TimestampFormat.TS_MILLIS,
    'TimestampFormat': JSON_TimestampFormat,
}

builtins.globals()['ZLogging::KRB'] = {
    'KRB_LOG': Log_ID.KRB_LOG,
}

builtins.globals()['ZLogging::Known'] = {
    'Known_CERTS_LOG': Log_ID.Known_CERTS_LOG,
    'Known_HOSTS_LOG': Log_ID.Known_HOSTS_LOG,
    'Known_MODBUS_LOG': Log_ID.Known_MODBUS_LOG,
    'Known_SERVICES_LOG': Log_ID.Known_SERVICES_LOG,
    'MODBUS_MASTER': Known_ModbusDeviceType.MODBUS_MASTER,
    'MODBUS_SLAVE': Known_ModbusDeviceType.MODBUS_SLAVE,
    'ModbusDeviceType': Known_ModbusDeviceType,
}

builtins.globals()['ZLogging::LDAP'] = {
    'BindAuthType': LDAP_BindAuthType,
    'BindAuthType_BIND_AUTH_SASL': LDAP_BindAuthType.BindAuthType_BIND_AUTH_SASL,
    'BindAuthType_BIND_AUTH_SIMPLE': LDAP_BindAuthType.BindAuthType_BIND_AUTH_SIMPLE,
    'BindAuthType_SICILY_NEGOTIATE': LDAP_BindAuthType.BindAuthType_SICILY_NEGOTIATE,
    'BindAuthType_SICILY_PACKAGE_DISCOVERY': LDAP_BindAuthType.BindAuthType_SICILY_PACKAGE_DISCOVERY,
    'BindAuthType_SICILY_RESPONSE': LDAP_BindAuthType.BindAuthType_SICILY_RESPONSE,
    'BindAuthType_Undef': LDAP_BindAuthType.BindAuthType_Undef,
    'ProtocolOpcode': LDAP_ProtocolOpcode,
    'ProtocolOpcode_ABANDON_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_ABANDON_REQUEST,
    'ProtocolOpcode_ADD_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_ADD_REQUEST,
    'ProtocolOpcode_ADD_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_ADD_RESPONSE,
    'ProtocolOpcode_BIND_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_BIND_REQUEST,
    'ProtocolOpcode_BIND_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_BIND_RESPONSE,
    'ProtocolOpcode_COMPARE_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_COMPARE_REQUEST,
    'ProtocolOpcode_COMPARE_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_COMPARE_RESPONSE,
    'ProtocolOpcode_DEL_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_DEL_REQUEST,
    'ProtocolOpcode_DEL_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_DEL_RESPONSE,
    'ProtocolOpcode_EXTENDED_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_EXTENDED_REQUEST,
    'ProtocolOpcode_EXTENDED_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_EXTENDED_RESPONSE,
    'ProtocolOpcode_INTERMEDIATE_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_INTERMEDIATE_RESPONSE,
    'ProtocolOpcode_MODIFY_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_MODIFY_REQUEST,
    'ProtocolOpcode_MODIFY_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_MODIFY_RESPONSE,
    'ProtocolOpcode_MOD_DN_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_MOD_DN_REQUEST,
    'ProtocolOpcode_MOD_DN_RESPONSE': LDAP_ProtocolOpcode.ProtocolOpcode_MOD_DN_RESPONSE,
    'ProtocolOpcode_SEARCH_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_SEARCH_REQUEST,
    'ProtocolOpcode_SEARCH_RESULT_DONE': LDAP_ProtocolOpcode.ProtocolOpcode_SEARCH_RESULT_DONE,
    'ProtocolOpcode_SEARCH_RESULT_ENTRY': LDAP_ProtocolOpcode.ProtocolOpcode_SEARCH_RESULT_ENTRY,
    'ProtocolOpcode_SEARCH_RESULT_REFERENCE': LDAP_ProtocolOpcode.ProtocolOpcode_SEARCH_RESULT_REFERENCE,
    'ProtocolOpcode_UNBIND_REQUEST': LDAP_ProtocolOpcode.ProtocolOpcode_UNBIND_REQUEST,
    'ProtocolOpcode_Undef': LDAP_ProtocolOpcode.ProtocolOpcode_Undef,
    'ResultCode': LDAP_ResultCode,
    'ResultCode_ADMIN_LIMIT_EXCEEDED': LDAP_ResultCode.ResultCode_ADMIN_LIMIT_EXCEEDED,
    'ResultCode_AFFECTS_MULTIPLE_DSAS': LDAP_ResultCode.ResultCode_AFFECTS_MULTIPLE_DSAS,
    'ResultCode_ALIAS_DEREFERENCING_PROBLEM': LDAP_ResultCode.ResultCode_ALIAS_DEREFERENCING_PROBLEM,
    'ResultCode_ALIAS_PROBLEM': LDAP_ResultCode.ResultCode_ALIAS_PROBLEM,
    'ResultCode_AMBIGUOUS_RESPONSE': LDAP_ResultCode.ResultCode_AMBIGUOUS_RESPONSE,
    'ResultCode_ASSERTION_FAILED': LDAP_ResultCode.ResultCode_ASSERTION_FAILED,
    'ResultCode_ATTRIBUTE_OR_VALUE_EXISTS': LDAP_ResultCode.ResultCode_ATTRIBUTE_OR_VALUE_EXISTS,
    'ResultCode_AUTHORIZATION_DENIED': LDAP_ResultCode.ResultCode_AUTHORIZATION_DENIED,
    'ResultCode_AUTH_METHOD_NOT_SUPPORTED': LDAP_ResultCode.ResultCode_AUTH_METHOD_NOT_SUPPORTED,
    'ResultCode_AUTH_UNKNOWN': LDAP_ResultCode.ResultCode_AUTH_UNKNOWN,
    'ResultCode_BUSY': LDAP_ResultCode.ResultCode_BUSY,
    'ResultCode_CANCELED': LDAP_ResultCode.ResultCode_CANCELED,
    'ResultCode_CANNOT_CANCEL': LDAP_ResultCode.ResultCode_CANNOT_CANCEL,
    'ResultCode_CLIENT_LOOP': LDAP_ResultCode.ResultCode_CLIENT_LOOP,
    'ResultCode_COMPARE_FALSE': LDAP_ResultCode.ResultCode_COMPARE_FALSE,
    'ResultCode_COMPARE_TRUE': LDAP_ResultCode.ResultCode_COMPARE_TRUE,
    'ResultCode_CONFIDENTIALITY_REQUIRED': LDAP_ResultCode.ResultCode_CONFIDENTIALITY_REQUIRED,
    'ResultCode_CONNECT_ERROR': LDAP_ResultCode.ResultCode_CONNECT_ERROR,
    'ResultCode_CONSTRAINT_VIOLATION': LDAP_ResultCode.ResultCode_CONSTRAINT_VIOLATION,
    'ResultCode_CONTROL_ERROR': LDAP_ResultCode.ResultCode_CONTROL_ERROR,
    'ResultCode_CONTROL_NOT_FOUND': LDAP_ResultCode.ResultCode_CONTROL_NOT_FOUND,
    'ResultCode_DECODING_ERROR': LDAP_ResultCode.ResultCode_DECODING_ERROR,
    'ResultCode_ENCODING_ERROR': LDAP_ResultCode.ResultCode_ENCODING_ERROR,
    'ResultCode_ENTRY_ALREADY_EXISTS': LDAP_ResultCode.ResultCode_ENTRY_ALREADY_EXISTS,
    'ResultCode_FILTER_ERROR': LDAP_ResultCode.ResultCode_FILTER_ERROR,
    'ResultCode_INAPPROPRIATE_AUTHENTICATION': LDAP_ResultCode.ResultCode_INAPPROPRIATE_AUTHENTICATION,
    'ResultCode_INAPPROPRIATE_MATCHING': LDAP_ResultCode.ResultCode_INAPPROPRIATE_MATCHING,
    'ResultCode_INSUFFICIENT_ACCESS_RIGHTS': LDAP_ResultCode.ResultCode_INSUFFICIENT_ACCESS_RIGHTS,
    'ResultCode_INTERMEDIATE_RESPONSE': LDAP_ResultCode.ResultCode_INTERMEDIATE_RESPONSE,
    'ResultCode_INVALID_ATTRIBUTE_SYNTAX': LDAP_ResultCode.ResultCode_INVALID_ATTRIBUTE_SYNTAX,
    'ResultCode_INVALID_CREDENTIALS': LDAP_ResultCode.ResultCode_INVALID_CREDENTIALS,
    'ResultCode_INVALID_DNSYNTAX': LDAP_ResultCode.ResultCode_INVALID_DNSYNTAX,
    'ResultCode_INVALID_RESPONSE': LDAP_ResultCode.ResultCode_INVALID_RESPONSE,
    'ResultCode_LCUP_INVALID_DATA': LDAP_ResultCode.ResultCode_LCUP_INVALID_DATA,
    'ResultCode_LCUP_RELOAD_REQUIRED': LDAP_ResultCode.ResultCode_LCUP_RELOAD_REQUIRED,
    'ResultCode_LCUP_UNSUPPORTED_SCHEME': LDAP_ResultCode.ResultCode_LCUP_UNSUPPORTED_SCHEME,
    'ResultCode_LOCAL_ERROR': LDAP_ResultCode.ResultCode_LOCAL_ERROR,
    'ResultCode_LOOP_DETECT': LDAP_ResultCode.ResultCode_LOOP_DETECT,
    'ResultCode_MORE_RESULTS_TO_RETURN': LDAP_ResultCode.ResultCode_MORE_RESULTS_TO_RETURN,
    'ResultCode_NAMING_VIOLATION': LDAP_ResultCode.ResultCode_NAMING_VIOLATION,
    'ResultCode_NOT_ALLOWED_ON_NON_LEAF': LDAP_ResultCode.ResultCode_NOT_ALLOWED_ON_NON_LEAF,
    'ResultCode_NOT_ALLOWED_ON_RDN': LDAP_ResultCode.ResultCode_NOT_ALLOWED_ON_RDN,
    'ResultCode_NOT_SUPPORTED': LDAP_ResultCode.ResultCode_NOT_SUPPORTED,
    'ResultCode_NO_MEMORY': LDAP_ResultCode.ResultCode_NO_MEMORY,
    'ResultCode_NO_RESULTS_RETURNED': LDAP_ResultCode.ResultCode_NO_RESULTS_RETURNED,
    'ResultCode_NO_SUCH_ATTRIBUTE': LDAP_ResultCode.ResultCode_NO_SUCH_ATTRIBUTE,
    'ResultCode_NO_SUCH_OBJECT': LDAP_ResultCode.ResultCode_NO_SUCH_OBJECT,
    'ResultCode_NO_SUCH_OPERATION': LDAP_ResultCode.ResultCode_NO_SUCH_OPERATION,
    'ResultCode_OBJECT_CLASS_MODS_PROHIBITED': LDAP_ResultCode.ResultCode_OBJECT_CLASS_MODS_PROHIBITED,
    'ResultCode_OBJECT_CLASS_VIOLATION': LDAP_ResultCode.ResultCode_OBJECT_CLASS_VIOLATION,
    'ResultCode_OFFSET_RANGE_ERROR': LDAP_ResultCode.ResultCode_OFFSET_RANGE_ERROR,
    'ResultCode_OPERATIONS_ERROR': LDAP_ResultCode.ResultCode_OPERATIONS_ERROR,
    'ResultCode_OTHER': LDAP_ResultCode.ResultCode_OTHER,
    'ResultCode_PARAM_ERROR': LDAP_ResultCode.ResultCode_PARAM_ERROR,
    'ResultCode_PARTIAL_RESULTS': LDAP_ResultCode.ResultCode_PARTIAL_RESULTS,
    'ResultCode_PROTOCOL_ERROR': LDAP_ResultCode.ResultCode_PROTOCOL_ERROR,
    'ResultCode_REFERRAL': LDAP_ResultCode.ResultCode_REFERRAL,
    'ResultCode_REFERRAL_LIMIT_EXCEEDED': LDAP_ResultCode.ResultCode_REFERRAL_LIMIT_EXCEEDED,
    'ResultCode_RESULTS_TOO_LARGE': LDAP_ResultCode.ResultCode_RESULTS_TOO_LARGE,
    'ResultCode_SASL_BIND_IN_PROGRESS': LDAP_ResultCode.ResultCode_SASL_BIND_IN_PROGRESS,
    'ResultCode_SERVER_DOWN': LDAP_ResultCode.ResultCode_SERVER_DOWN,
    'ResultCode_SIZE_LIMIT_EXCEEDED': LDAP_ResultCode.ResultCode_SIZE_LIMIT_EXCEEDED,
    'ResultCode_SORT_CONTROL_MISSING': LDAP_ResultCode.ResultCode_SORT_CONTROL_MISSING,
    'ResultCode_STRONGER_AUTH_REQUIRED': LDAP_ResultCode.ResultCode_STRONGER_AUTH_REQUIRED,
    'ResultCode_SUCCESS': LDAP_ResultCode.ResultCode_SUCCESS,
    'ResultCode_TIMEOUT': LDAP_ResultCode.ResultCode_TIMEOUT,
    'ResultCode_TIME_LIMIT_EXCEEDED': LDAP_ResultCode.ResultCode_TIME_LIMIT_EXCEEDED,
    'ResultCode_TLS_NOT_SUPPORTED': LDAP_ResultCode.ResultCode_TLS_NOT_SUPPORTED,
    'ResultCode_TOO_LATE': LDAP_ResultCode.ResultCode_TOO_LATE,
    'ResultCode_UNAVAILABLE': LDAP_ResultCode.ResultCode_UNAVAILABLE,
    'ResultCode_UNAVAILABLE_CRITICAL_EXTENSION': LDAP_ResultCode.ResultCode_UNAVAILABLE_CRITICAL_EXTENSION,
    'ResultCode_UNDEFINED_ATTRIBUTE_TYPE': LDAP_ResultCode.ResultCode_UNDEFINED_ATTRIBUTE_TYPE,
    'ResultCode_UNKNOWN_TYPE': LDAP_ResultCode.ResultCode_UNKNOWN_TYPE,
    'ResultCode_UNWILLING_TO_PERFORM': LDAP_ResultCode.ResultCode_UNWILLING_TO_PERFORM,
    'ResultCode_USER_CANCELED': LDAP_ResultCode.ResultCode_USER_CANCELED,
    'ResultCode_Undef': LDAP_ResultCode.ResultCode_Undef,
    'SearchDerefAlias': LDAP_SearchDerefAlias,
    'SearchDerefAlias_DEREF_ALWAYS': LDAP_SearchDerefAlias.SearchDerefAlias_DEREF_ALWAYS,
    'SearchDerefAlias_DEREF_FINDING_BASE': LDAP_SearchDerefAlias.SearchDerefAlias_DEREF_FINDING_BASE,
    'SearchDerefAlias_DEREF_IN_SEARCHING': LDAP_SearchDerefAlias.SearchDerefAlias_DEREF_IN_SEARCHING,
    'SearchDerefAlias_DEREF_NEVER': LDAP_SearchDerefAlias.SearchDerefAlias_DEREF_NEVER,
    'SearchDerefAlias_Undef': LDAP_SearchDerefAlias.SearchDerefAlias_Undef,
    'SearchScope': LDAP_SearchScope,
    'SearchScope_SEARCH_BASE': LDAP_SearchScope.SearchScope_SEARCH_BASE,
    'SearchScope_SEARCH_SINGLE': LDAP_SearchScope.SearchScope_SEARCH_SINGLE,
    'SearchScope_SEARCH_TREE': LDAP_SearchScope.SearchScope_SEARCH_TREE,
    'SearchScope_Undef': LDAP_SearchScope.SearchScope_Undef,
}

builtins.globals()['ZLogging::LoadBalancing'] = {
    'AUTO_BPF': LoadBalancing_Method.AUTO_BPF,
    'Method': LoadBalancing_Method,
}

builtins.globals()['ZLogging::LoadedScripts'] = {
    'LoadedScripts_LOG': Log_ID.LoadedScripts_LOG,
}

builtins.globals()['ZLogging::Log'] = {
    'ID': Log_ID,
    'PRINTLOG': Log_ID.PRINTLOG,
    'PrintLogType': Log_PrintLogType,
    'REDIRECT_ALL': Log_PrintLogType.REDIRECT_ALL,
    'REDIRECT_NONE': Log_PrintLogType.REDIRECT_NONE,
    'REDIRECT_STDOUT': Log_PrintLogType.REDIRECT_STDOUT,
    'UNKNOWN': Log_ID.UNKNOWN,
    'WRITER_ASCII': Log_Writer.WRITER_ASCII,
    'WRITER_NONE': Log_Writer.WRITER_NONE,
    'WRITER_SQLITE': Log_Writer.WRITER_SQLITE,
    'Writer': Log_Writer,
}

builtins.globals()['ZLogging::MOUNT3'] = {
    'AUTH_DES': MOUNT3_auth_flavor_t.AUTH_DES,
    'AUTH_NULL': MOUNT3_auth_flavor_t.AUTH_NULL,
    'AUTH_SHORT': MOUNT3_auth_flavor_t.AUTH_SHORT,
    'AUTH_UNIX': MOUNT3_auth_flavor_t.AUTH_UNIX,
    'MNT3ERR_ACCES': MOUNT3_status_t.MNT3ERR_ACCES,
    'MNT3ERR_INVAL': MOUNT3_status_t.MNT3ERR_INVAL,
    'MNT3ERR_IO': MOUNT3_status_t.MNT3ERR_IO,
    'MNT3ERR_NAMETOOLONG': MOUNT3_status_t.MNT3ERR_NAMETOOLONG,
    'MNT3ERR_NOENT': MOUNT3_status_t.MNT3ERR_NOENT,
    'MNT3ERR_NOTDIR': MOUNT3_status_t.MNT3ERR_NOTDIR,
    'MNT3ERR_NOTSUPP': MOUNT3_status_t.MNT3ERR_NOTSUPP,
    'MNT3ERR_PERM': MOUNT3_status_t.MNT3ERR_PERM,
    'MNT3ERR_SERVERFAULT': MOUNT3_status_t.MNT3ERR_SERVERFAULT,
    'MNT3_OK': MOUNT3_status_t.MNT3_OK,
    'MOUNT3ERR_UNKNOWN': MOUNT3_status_t.MOUNT3ERR_UNKNOWN,
    'PROC_DUMP': MOUNT3_proc_t.PROC_DUMP,
    'PROC_END_OF_PROCS': MOUNT3_proc_t.PROC_END_OF_PROCS,
    'PROC_EXPORT': MOUNT3_proc_t.PROC_EXPORT,
    'PROC_MNT': MOUNT3_proc_t.PROC_MNT,
    'PROC_NULL': MOUNT3_proc_t.PROC_NULL,
    'PROC_UMNT': MOUNT3_proc_t.PROC_UMNT,
    'PROC_UMNT_ALL': MOUNT3_proc_t.PROC_UMNT_ALL,
    'auth_flavor_t': MOUNT3_auth_flavor_t,
    'proc_t': MOUNT3_proc_t,
    'status_t': MOUNT3_status_t,
}

builtins.globals()['ZLogging::MQTT'] = {
    'MQTT_CONNECT_LOG': Log_ID.MQTT_CONNECT_LOG,
    'MQTT_PUBLISH_LOG': Log_ID.MQTT_PUBLISH_LOG,
    'MQTT_SUBSCRIBE_LOG': Log_ID.MQTT_SUBSCRIBE_LOG,
    'SUBSCRIBE': MQTT_SubUnsub.SUBSCRIBE,
    'SubUnsub': MQTT_SubUnsub,
    'UNSUBSCRIBE': MQTT_SubUnsub.UNSUBSCRIBE,
}

builtins.globals()['ZLogging::Management'] = {
    'AGENT': Management_Role.AGENT,
    'CONTROLLER': Management_Role.CONTROLLER,
    'CRASHED': Management_State.CRASHED,
    'FAILED': Management_State.FAILED,
    'NODE': Management_Role.NODE,
    'NONE': Management_Role.NONE,
    'PENDING': Management_State.PENDING,
    'RUNNING': Management_State.RUNNING,
    'Role': Management_Role,
    'STOPPED': Management_State.STOPPED,
    'State': Management_State,
    'UNKNOWN': Management_State.UNKNOWN,
}

builtins.globals()['ZLogging::Management::Controller::Runtime'] = {
    'ConfigState': Management_Controller_Runtime_ConfigState,
    'DEPLOYED': Management_Controller_Runtime_ConfigState.DEPLOYED,
    'READY': Management_Controller_Runtime_ConfigState.READY,
    'STAGED': Management_Controller_Runtime_ConfigState.STAGED,
}

builtins.globals()['ZLogging::Management::Log'] = {
    'DEBUG': Management_Log_Level.DEBUG,
    'ERROR': Management_Log_Level.ERROR,
    'INFO': Management_Log_Level.INFO,
    'Level': Management_Log_Level,
    'Management_LOG': Log_ID.Management_LOG,
    'WARNING': Management_Log_Level.WARNING,
}

builtins.globals()['ZLogging::Modbus'] = {
    'Modbus_LOG': Log_ID.Modbus_LOG,
    'Modbus_REGISTER_CHANGE_LOG': Log_ID.Modbus_REGISTER_CHANGE_LOG,
}

builtins.globals()['ZLogging::MySQL'] = {
    'MySQL_SERVER': Software_Type.MySQL_SERVER,
}

builtins.globals()['ZLogging::NFS3'] = {
    'DATA_SYNC': NFS3_stable_how_t.DATA_SYNC,
    'DONT_CHANGE': NFS3_time_how_t.DONT_CHANGE,
    'EXCLUSIVE': NFS3_createmode_t.EXCLUSIVE,
    'FILE_SYNC': NFS3_stable_how_t.FILE_SYNC,
    'FTYPE_BLK': NFS3_file_type_t.FTYPE_BLK,
    'FTYPE_CHR': NFS3_file_type_t.FTYPE_CHR,
    'FTYPE_DIR': NFS3_file_type_t.FTYPE_DIR,
    'FTYPE_FIFO': NFS3_file_type_t.FTYPE_FIFO,
    'FTYPE_LNK': NFS3_file_type_t.FTYPE_LNK,
    'FTYPE_REG': NFS3_file_type_t.FTYPE_REG,
    'FTYPE_SOCK': NFS3_file_type_t.FTYPE_SOCK,
    'GUARDED': NFS3_createmode_t.GUARDED,
    'NFS3ERR_ACCES': NFS3_status_t.NFS3ERR_ACCES,
    'NFS3ERR_BADHANDLE': NFS3_status_t.NFS3ERR_BADHANDLE,
    'NFS3ERR_BADTYPE': NFS3_status_t.NFS3ERR_BADTYPE,
    'NFS3ERR_BAD_COOKIE': NFS3_status_t.NFS3ERR_BAD_COOKIE,
    'NFS3ERR_DQUOT': NFS3_status_t.NFS3ERR_DQUOT,
    'NFS3ERR_EXIST': NFS3_status_t.NFS3ERR_EXIST,
    'NFS3ERR_FBIG': NFS3_status_t.NFS3ERR_FBIG,
    'NFS3ERR_INVAL': NFS3_status_t.NFS3ERR_INVAL,
    'NFS3ERR_IO': NFS3_status_t.NFS3ERR_IO,
    'NFS3ERR_ISDIR': NFS3_status_t.NFS3ERR_ISDIR,
    'NFS3ERR_JUKEBOX': NFS3_status_t.NFS3ERR_JUKEBOX,
    'NFS3ERR_MLINK': NFS3_status_t.NFS3ERR_MLINK,
    'NFS3ERR_NAMETOOLONG': NFS3_status_t.NFS3ERR_NAMETOOLONG,
    'NFS3ERR_NODEV': NFS3_status_t.NFS3ERR_NODEV,
    'NFS3ERR_NOENT': NFS3_status_t.NFS3ERR_NOENT,
    'NFS3ERR_NOSPC': NFS3_status_t.NFS3ERR_NOSPC,
    'NFS3ERR_NOTDIR': NFS3_status_t.NFS3ERR_NOTDIR,
    'NFS3ERR_NOTEMPTY': NFS3_status_t.NFS3ERR_NOTEMPTY,
    'NFS3ERR_NOTSUPP': NFS3_status_t.NFS3ERR_NOTSUPP,
    'NFS3ERR_NOT_SYNC': NFS3_status_t.NFS3ERR_NOT_SYNC,
    'NFS3ERR_NXIO': NFS3_status_t.NFS3ERR_NXIO,
    'NFS3ERR_OK': NFS3_status_t.NFS3ERR_OK,
    'NFS3ERR_PERM': NFS3_status_t.NFS3ERR_PERM,
    'NFS3ERR_REMOTE': NFS3_status_t.NFS3ERR_REMOTE,
    'NFS3ERR_ROFS': NFS3_status_t.NFS3ERR_ROFS,
    'NFS3ERR_SERVERFAULT': NFS3_status_t.NFS3ERR_SERVERFAULT,
    'NFS3ERR_STALE': NFS3_status_t.NFS3ERR_STALE,
    'NFS3ERR_TOOSMALL': NFS3_status_t.NFS3ERR_TOOSMALL,
    'NFS3ERR_UNKNOWN': NFS3_status_t.NFS3ERR_UNKNOWN,
    'NFS3ERR_XDEV': NFS3_status_t.NFS3ERR_XDEV,
    'PROC_ACCESS': NFS3_proc_t.PROC_ACCESS,
    'PROC_COMMIT': NFS3_proc_t.PROC_COMMIT,
    'PROC_CREATE': NFS3_proc_t.PROC_CREATE,
    'PROC_END_OF_PROCS': NFS3_proc_t.PROC_END_OF_PROCS,
    'PROC_FSINFO': NFS3_proc_t.PROC_FSINFO,
    'PROC_FSSTAT': NFS3_proc_t.PROC_FSSTAT,
    'PROC_GETATTR': NFS3_proc_t.PROC_GETATTR,
    'PROC_LINK': NFS3_proc_t.PROC_LINK,
    'PROC_LOOKUP': NFS3_proc_t.PROC_LOOKUP,
    'PROC_MKDIR': NFS3_proc_t.PROC_MKDIR,
    'PROC_MKNOD': NFS3_proc_t.PROC_MKNOD,
    'PROC_NULL': NFS3_proc_t.PROC_NULL,
    'PROC_PATHCONF': NFS3_proc_t.PROC_PATHCONF,
    'PROC_READ': NFS3_proc_t.PROC_READ,
    'PROC_READDIR': NFS3_proc_t.PROC_READDIR,
    'PROC_READDIRPLUS': NFS3_proc_t.PROC_READDIRPLUS,
    'PROC_READLINK': NFS3_proc_t.PROC_READLINK,
    'PROC_REMOVE': NFS3_proc_t.PROC_REMOVE,
    'PROC_RENAME': NFS3_proc_t.PROC_RENAME,
    'PROC_RMDIR': NFS3_proc_t.PROC_RMDIR,
    'PROC_SETATTR': NFS3_proc_t.PROC_SETATTR,
    'PROC_SYMLINK': NFS3_proc_t.PROC_SYMLINK,
    'PROC_WRITE': NFS3_proc_t.PROC_WRITE,
    'SET_TO_CLIENT_TIME': NFS3_time_how_t.SET_TO_CLIENT_TIME,
    'SET_TO_SERVER_TIME': NFS3_time_how_t.SET_TO_SERVER_TIME,
    'UNCHECKED': NFS3_createmode_t.UNCHECKED,
    'UNSTABLE': NFS3_stable_how_t.UNSTABLE,
    'createmode_t': NFS3_createmode_t,
    'file_type_t': NFS3_file_type_t,
    'proc_t': NFS3_proc_t,
    'stable_how_t': NFS3_stable_how_t,
    'status_t': NFS3_status_t,
    'time_how_t': NFS3_time_how_t,
}

builtins.globals()['ZLogging::NTLM'] = {
    'NTLM_LOG': Log_ID.NTLM_LOG,
}

builtins.globals()['ZLogging::NTP'] = {
    'NTP_LOG': Log_ID.NTP_LOG,
}

builtins.globals()['ZLogging::NetControl'] = {
    'ADDED': NetControl_CatchReleaseActions.ADDED,
    'ADDRESS': NetControl_EntityType.ADDRESS,
    'CONNECTION': NetControl_EntityType.CONNECTION,
    'CatchReleaseActions': NetControl_CatchReleaseActions,
    'DROP': NetControl_RuleType.DROP,
    'DROPPED': NetControl_CatchReleaseActions.DROPPED,
    'DROP_REQUESTED': NetControl_CatchReleaseActions.DROP_REQUESTED,
    'ERROR': NetControl_InfoCategory.ERROR,
    'EXISTS': NetControl_InfoState.EXISTS,
    'EntityType': NetControl_EntityType,
    'FAILED': NetControl_InfoState.FAILED,
    'FLOW': NetControl_EntityType.FLOW,
    'FORGOTTEN': NetControl_CatchReleaseActions.FORGOTTEN,
    'FORWARD': NetControl_TargetType.FORWARD,
    'INFO': NetControl_CatchReleaseActions.INFO,
    'InfoCategory': NetControl_InfoCategory,
    'InfoState': NetControl_InfoState,
    'MAC': NetControl_EntityType.MAC,
    'MESSAGE': NetControl_InfoCategory.MESSAGE,
    'MODIFY': NetControl_RuleType.MODIFY,
    'MONITOR': NetControl_TargetType.MONITOR,
    'NetControl_CATCH_RELEASE': Log_ID.NetControl_CATCH_RELEASE,
    'NetControl_DROP_LOG': Log_ID.NetControl_DROP_LOG,
    'NetControl_LOG': Log_ID.NetControl_LOG,
    'NetControl_SHUNT': Log_ID.NetControl_SHUNT,
    'REDIRECT': NetControl_RuleType.REDIRECT,
    'REMOVED': NetControl_InfoState.REMOVED,
    'REQUESTED': NetControl_InfoState.REQUESTED,
    'RULE': NetControl_InfoCategory.RULE,
    'RuleType': NetControl_RuleType,
    'SEEN_AGAIN': NetControl_CatchReleaseActions.SEEN_AGAIN,
    'SUCCEEDED': NetControl_InfoState.SUCCEEDED,
    'TIMEOUT': NetControl_InfoState.TIMEOUT,
    'TargetType': NetControl_TargetType,
    'UNBLOCK': NetControl_CatchReleaseActions.UNBLOCK,
    'WHITELIST': NetControl_RuleType.WHITELIST,
}

builtins.globals()['ZLogging::Notice'] = {
    'ACTION_ADD_GEODATA': Notice_Action.ACTION_ADD_GEODATA,
    'ACTION_ALARM': Notice_Action.ACTION_ALARM,
    'ACTION_DROP': Notice_Action.ACTION_DROP,
    'ACTION_EMAIL': Notice_Action.ACTION_EMAIL,
    'ACTION_EMAIL_ADMIN': Notice_Action.ACTION_EMAIL_ADMIN,
    'ACTION_LOG': Notice_Action.ACTION_LOG,
    'ACTION_NONE': Notice_Action.ACTION_NONE,
    'ACTION_PAGE': Notice_Action.ACTION_PAGE,
    'Action': Notice_Action,
    'Notice_ALARM_LOG': Log_ID.Notice_ALARM_LOG,
    'Notice_LOG': Log_ID.Notice_LOG,
    'Tally': Notice_Type.Tally,
    'Type': Notice_Type,
}

builtins.globals()['ZLogging::OCSP'] = {
    'OCSP_LOG': Log_ID.OCSP_LOG,
}

builtins.globals()['ZLogging::OS'] = {
    'OS_WINDOWS': Software_Type.OS_WINDOWS,
}

builtins.globals()['ZLogging::OpenFlow'] = {
    'BROKER': OpenFlow_Plugin.BROKER,
    'INVALID': OpenFlow_Plugin.INVALID,
    'OFLOG': OpenFlow_Plugin.OFLOG,
    'OFPAT_ENQUEUE': OpenFlow_ofp_action_type.OFPAT_ENQUEUE,
    'OFPAT_OUTPUT': OpenFlow_ofp_action_type.OFPAT_OUTPUT,
    'OFPAT_SET_DL_DST': OpenFlow_ofp_action_type.OFPAT_SET_DL_DST,
    'OFPAT_SET_DL_SRC': OpenFlow_ofp_action_type.OFPAT_SET_DL_SRC,
    'OFPAT_SET_NW_DST': OpenFlow_ofp_action_type.OFPAT_SET_NW_DST,
    'OFPAT_SET_NW_SRC': OpenFlow_ofp_action_type.OFPAT_SET_NW_SRC,
    'OFPAT_SET_NW_TOS': OpenFlow_ofp_action_type.OFPAT_SET_NW_TOS,
    'OFPAT_SET_TP_DST': OpenFlow_ofp_action_type.OFPAT_SET_TP_DST,
    'OFPAT_SET_TP_SRC': OpenFlow_ofp_action_type.OFPAT_SET_TP_SRC,
    'OFPAT_SET_VLAN_PCP': OpenFlow_ofp_action_type.OFPAT_SET_VLAN_PCP,
    'OFPAT_SET_VLAN_VID': OpenFlow_ofp_action_type.OFPAT_SET_VLAN_VID,
    'OFPAT_STRIP_VLAN': OpenFlow_ofp_action_type.OFPAT_STRIP_VLAN,
    'OFPAT_VENDOR': OpenFlow_ofp_action_type.OFPAT_VENDOR,
    'OFPC_FRAG_DROP': OpenFlow_ofp_config_flags.OFPC_FRAG_DROP,
    'OFPC_FRAG_MASK': OpenFlow_ofp_config_flags.OFPC_FRAG_MASK,
    'OFPC_FRAG_NORMAL': OpenFlow_ofp_config_flags.OFPC_FRAG_NORMAL,
    'OFPC_FRAG_REASM': OpenFlow_ofp_config_flags.OFPC_FRAG_REASM,
    'OFPFC_ADD': OpenFlow_ofp_flow_mod_command.OFPFC_ADD,
    'OFPFC_DELETE': OpenFlow_ofp_flow_mod_command.OFPFC_DELETE,
    'OFPFC_DELETE_STRICT': OpenFlow_ofp_flow_mod_command.OFPFC_DELETE_STRICT,
    'OFPFC_MODIFY': OpenFlow_ofp_flow_mod_command.OFPFC_MODIFY,
    'OFPFC_MODIFY_STRICT': OpenFlow_ofp_flow_mod_command.OFPFC_MODIFY_STRICT,
    'OpenFlow_LOG': Log_ID.OpenFlow_LOG,
    'Plugin': OpenFlow_Plugin,
    'RYU': OpenFlow_Plugin.RYU,
    'ofp_action_type': OpenFlow_ofp_action_type,
    'ofp_config_flags': OpenFlow_ofp_config_flags,
    'ofp_flow_mod_command': OpenFlow_ofp_flow_mod_command,
}

builtins.globals()['ZLogging::PE'] = {
    'PE_LOG': Log_ID.PE_LOG,
}

builtins.globals()['ZLogging::PacketAnalyzer'] = {
    'ANALYZER_ARP': PacketAnalyzer_Tag.ANALYZER_ARP,
    'ANALYZER_AYIYA': PacketAnalyzer_Tag.ANALYZER_AYIYA,
    'ANALYZER_ETHERNET': PacketAnalyzer_Tag.ANALYZER_ETHERNET,
    'ANALYZER_FDDI': PacketAnalyzer_Tag.ANALYZER_FDDI,
    'ANALYZER_GENEVE': PacketAnalyzer_Tag.ANALYZER_GENEVE,
    'ANALYZER_GRE': PacketAnalyzer_Tag.ANALYZER_GRE,
    'ANALYZER_GTPV1': PacketAnalyzer_Tag.ANALYZER_GTPV1,
    'ANALYZER_ICMP': PacketAnalyzer_Tag.ANALYZER_ICMP,
    'ANALYZER_IEEE802_11': PacketAnalyzer_Tag.ANALYZER_IEEE802_11,
    'ANALYZER_IEEE802_11_RADIO': PacketAnalyzer_Tag.ANALYZER_IEEE802_11_RADIO,
    'ANALYZER_IGMP': PacketAnalyzer_Tag.ANALYZER_IGMP,
    'ANALYZER_IP': PacketAnalyzer_Tag.ANALYZER_IP,
    'ANALYZER_IPTUNNEL': PacketAnalyzer_Tag.ANALYZER_IPTUNNEL,
    'ANALYZER_LINUXSLL': PacketAnalyzer_Tag.ANALYZER_LINUXSLL,
    'ANALYZER_LINUXSLL2': PacketAnalyzer_Tag.ANALYZER_LINUXSLL2,
    'ANALYZER_LLC': PacketAnalyzer_Tag.ANALYZER_LLC,
    'ANALYZER_MPLS': PacketAnalyzer_Tag.ANALYZER_MPLS,
    'ANALYZER_NFLOG': PacketAnalyzer_Tag.ANALYZER_NFLOG,
    'ANALYZER_NOVELL_802_3': PacketAnalyzer_Tag.ANALYZER_NOVELL_802_3,
    'ANALYZER_NULL': PacketAnalyzer_Tag.ANALYZER_NULL,
    'ANALYZER_PBB': PacketAnalyzer_Tag.ANALYZER_PBB,
    'ANALYZER_PPP': PacketAnalyzer_Tag.ANALYZER_PPP,
    'ANALYZER_PPPOE': PacketAnalyzer_Tag.ANALYZER_PPPOE,
    'ANALYZER_PPPSERIAL': PacketAnalyzer_Tag.ANALYZER_PPPSERIAL,
    'ANALYZER_ROOT': PacketAnalyzer_Tag.ANALYZER_ROOT,
    'ANALYZER_SKIP': PacketAnalyzer_Tag.ANALYZER_SKIP,
    'ANALYZER_SNAP': PacketAnalyzer_Tag.ANALYZER_SNAP,
    'ANALYZER_TCP': PacketAnalyzer_Tag.ANALYZER_TCP,
    'ANALYZER_TEREDO': PacketAnalyzer_Tag.ANALYZER_TEREDO,
    'ANALYZER_UDP': PacketAnalyzer_Tag.ANALYZER_UDP,
    'ANALYZER_UNKNOWN_IP_TRANSPORT': PacketAnalyzer_Tag.ANALYZER_UNKNOWN_IP_TRANSPORT,
    'ANALYZER_VLAN': PacketAnalyzer_Tag.ANALYZER_VLAN,
    'ANALYZER_VNTAG': PacketAnalyzer_Tag.ANALYZER_VNTAG,
    'ANALYZER_VXLAN': PacketAnalyzer_Tag.ANALYZER_VXLAN,
    'Tag': PacketAnalyzer_Tag,
}

builtins.globals()['ZLogging::PacketFilter'] = {
    'PacketFilter_Cannot_BPF_Shunt_Conn': Notice_Type.PacketFilter_Cannot_BPF_Shunt_Conn,
    'PacketFilter_Compile_Failure': Notice_Type.PacketFilter_Compile_Failure,
    'PacketFilter_DefaultPcapFilter': zeek_PcapFilterID.PacketFilter_DefaultPcapFilter,
    'PacketFilter_Dropped_Packets': Notice_Type.PacketFilter_Dropped_Packets,
    'PacketFilter_FilterTester': zeek_PcapFilterID.PacketFilter_FilterTester,
    'PacketFilter_Install_Failure': Notice_Type.PacketFilter_Install_Failure,
    'PacketFilter_LOG': Log_ID.PacketFilter_LOG,
    'PacketFilter_No_More_Conn_Shunts_Available': Notice_Type.PacketFilter_No_More_Conn_Shunts_Available,
    'PacketFilter_Too_Long_To_Compile_Filter': Notice_Type.PacketFilter_Too_Long_To_Compile_Filter,
}

builtins.globals()['ZLogging::Pcap'] = {
    'fatal': Pcap_filter_state.fatal,
    'filter_state': Pcap_filter_state,
    'ok': Pcap_filter_state.ok,
    'warning': Pcap_filter_state.warning,
}

builtins.globals()['ZLogging::ProtocolDetector'] = {
    'BOTH': ProtocolDetector_dir.BOTH,
    'INCOMING': ProtocolDetector_dir.INCOMING,
    'NONE': ProtocolDetector_dir.NONE,
    'OUTGOING': ProtocolDetector_dir.OUTGOING,
    'ProtocolDetector_Protocol_Found': Notice_Type.ProtocolDetector_Protocol_Found,
    'ProtocolDetector_Server_Found': Notice_Type.ProtocolDetector_Server_Found,
    'dir': ProtocolDetector_dir,
}

builtins.globals()['ZLogging::RADIUS'] = {
    'RADIUS_LOG': Log_ID.RADIUS_LOG,
}

builtins.globals()['ZLogging::RDP'] = {
    'RDP_LOG': Log_ID.RDP_LOG,
}

builtins.globals()['ZLogging::RFB'] = {
    'RFB_LOG': Log_ID.RFB_LOG,
}

builtins.globals()['ZLogging::Redis'] = {
    'RedisCommand': Redis_RedisCommand,
    'RedisCommand_APPEND': Redis_RedisCommand.RedisCommand_APPEND,
    'RedisCommand_AUTH': Redis_RedisCommand.RedisCommand_AUTH,
    'RedisCommand_BITCOUNT': Redis_RedisCommand.RedisCommand_BITCOUNT,
    'RedisCommand_BITFIELD': Redis_RedisCommand.RedisCommand_BITFIELD,
    'RedisCommand_BITFIELD_RO': Redis_RedisCommand.RedisCommand_BITFIELD_RO,
    'RedisCommand_BITOP': Redis_RedisCommand.RedisCommand_BITOP,
    'RedisCommand_BITPOS': Redis_RedisCommand.RedisCommand_BITPOS,
    'RedisCommand_BLMPOP': Redis_RedisCommand.RedisCommand_BLMPOP,
    'RedisCommand_BLPOP': Redis_RedisCommand.RedisCommand_BLPOP,
    'RedisCommand_BRPOP': Redis_RedisCommand.RedisCommand_BRPOP,
    'RedisCommand_CLIENT': Redis_RedisCommand.RedisCommand_CLIENT,
    'RedisCommand_COPY': Redis_RedisCommand.RedisCommand_COPY,
    'RedisCommand_DECR': Redis_RedisCommand.RedisCommand_DECR,
    'RedisCommand_DECRBY': Redis_RedisCommand.RedisCommand_DECRBY,
    'RedisCommand_DEL': Redis_RedisCommand.RedisCommand_DEL,
    'RedisCommand_DUMP': Redis_RedisCommand.RedisCommand_DUMP,
    'RedisCommand_EXISTS': Redis_RedisCommand.RedisCommand_EXISTS,
    'RedisCommand_EXPIRE': Redis_RedisCommand.RedisCommand_EXPIRE,
    'RedisCommand_EXPIREAT': Redis_RedisCommand.RedisCommand_EXPIREAT,
    'RedisCommand_EXPIRETIME': Redis_RedisCommand.RedisCommand_EXPIRETIME,
    'RedisCommand_GET': Redis_RedisCommand.RedisCommand_GET,
    'RedisCommand_GETBIT': Redis_RedisCommand.RedisCommand_GETBIT,
    'RedisCommand_GETDEL': Redis_RedisCommand.RedisCommand_GETDEL,
    'RedisCommand_GETEX': Redis_RedisCommand.RedisCommand_GETEX,
    'RedisCommand_GETRANGE': Redis_RedisCommand.RedisCommand_GETRANGE,
    'RedisCommand_GETSET': Redis_RedisCommand.RedisCommand_GETSET,
    'RedisCommand_HDEL': Redis_RedisCommand.RedisCommand_HDEL,
    'RedisCommand_HELLO': Redis_RedisCommand.RedisCommand_HELLO,
    'RedisCommand_HGET': Redis_RedisCommand.RedisCommand_HGET,
    'RedisCommand_HSET': Redis_RedisCommand.RedisCommand_HSET,
    'RedisCommand_INCR': Redis_RedisCommand.RedisCommand_INCR,
    'RedisCommand_INCRBY': Redis_RedisCommand.RedisCommand_INCRBY,
    'RedisCommand_KEYS': Redis_RedisCommand.RedisCommand_KEYS,
    'RedisCommand_MGET': Redis_RedisCommand.RedisCommand_MGET,
    'RedisCommand_MOVE': Redis_RedisCommand.RedisCommand_MOVE,
    'RedisCommand_MSET': Redis_RedisCommand.RedisCommand_MSET,
    'RedisCommand_PERSIST': Redis_RedisCommand.RedisCommand_PERSIST,
    'RedisCommand_PSUBSCRIBE': Redis_RedisCommand.RedisCommand_PSUBSCRIBE,
    'RedisCommand_PUNSUBSCRIBE': Redis_RedisCommand.RedisCommand_PUNSUBSCRIBE,
    'RedisCommand_QUIT': Redis_RedisCommand.RedisCommand_QUIT,
    'RedisCommand_RENAME': Redis_RedisCommand.RedisCommand_RENAME,
    'RedisCommand_RESET': Redis_RedisCommand.RedisCommand_RESET,
    'RedisCommand_SET': Redis_RedisCommand.RedisCommand_SET,
    'RedisCommand_SSUBSCRIBE': Redis_RedisCommand.RedisCommand_SSUBSCRIBE,
    'RedisCommand_STRLEN': Redis_RedisCommand.RedisCommand_STRLEN,
    'RedisCommand_SUBSCRIBE': Redis_RedisCommand.RedisCommand_SUBSCRIBE,
    'RedisCommand_SUNSUBSCRIBE': Redis_RedisCommand.RedisCommand_SUNSUBSCRIBE,
    'RedisCommand_TTL': Redis_RedisCommand.RedisCommand_TTL,
    'RedisCommand_TYPE': Redis_RedisCommand.RedisCommand_TYPE,
    'RedisCommand_UNSUBSCRIBE': Redis_RedisCommand.RedisCommand_UNSUBSCRIBE,
    'RedisCommand_Undef': Redis_RedisCommand.RedisCommand_Undef,
    'ReplyType': Redis_ReplyType,
    'ReplyType_Error': Redis_ReplyType.ReplyType_Error,
    'ReplyType_Push': Redis_ReplyType.ReplyType_Push,
    'ReplyType_Reply': Redis_ReplyType.ReplyType_Reply,
    'ReplyType_Undef': Redis_ReplyType.ReplyType_Undef,
}

builtins.globals()['ZLogging::Reporter'] = {
    'ERROR': Reporter_Level.ERROR,
    'INFO': Reporter_Level.INFO,
    'Level': Reporter_Level,
    'Reporter_LOG': Log_ID.Reporter_LOG,
    'WARNING': Reporter_Level.WARNING,
}

builtins.globals()['ZLogging::SIP'] = {
    'SIP_LOG': Log_ID.SIP_LOG,
}

builtins.globals()['ZLogging::SMB'] = {
    'Action': SMB_Action,
    'FILE_CLOSE': SMB_Action.FILE_CLOSE,
    'FILE_DELETE': SMB_Action.FILE_DELETE,
    'FILE_OPEN': SMB_Action.FILE_OPEN,
    'FILE_READ': SMB_Action.FILE_READ,
    'FILE_RENAME': SMB_Action.FILE_RENAME,
    'FILE_SET_ATTRIBUTE': SMB_Action.FILE_SET_ATTRIBUTE,
    'FILE_WRITE': SMB_Action.FILE_WRITE,
    'PIPE_CLOSE': SMB_Action.PIPE_CLOSE,
    'PIPE_OPEN': SMB_Action.PIPE_OPEN,
    'PIPE_READ': SMB_Action.PIPE_READ,
    'PIPE_WRITE': SMB_Action.PIPE_WRITE,
    'PRINT_CLOSE': SMB_Action.PRINT_CLOSE,
    'PRINT_OPEN': SMB_Action.PRINT_OPEN,
    'PRINT_READ': SMB_Action.PRINT_READ,
    'PRINT_WRITE': SMB_Action.PRINT_WRITE,
    'SMB_CMD_LOG': Log_ID.SMB_CMD_LOG,
    'SMB_FILES_LOG': Log_ID.SMB_FILES_LOG,
    'SMB_IN_FILE_NAME': Intel_Where.SMB_IN_FILE_NAME,
    'SMB_MAPPING_LOG': Log_ID.SMB_MAPPING_LOG,
}

builtins.globals()['ZLogging::SMTP'] = {
    'SMTP_Blocklist_Blocked_Host': Notice_Type.SMTP_Blocklist_Blocked_Host,
    'SMTP_Blocklist_Error_Message': Notice_Type.SMTP_Blocklist_Error_Message,
    'SMTP_IN_CC': Intel_Where.SMTP_IN_CC,
    'SMTP_IN_FROM': Intel_Where.SMTP_IN_FROM,
    'SMTP_IN_HEADER': Intel_Where.SMTP_IN_HEADER,
    'SMTP_IN_MAIL_FROM': Intel_Where.SMTP_IN_MAIL_FROM,
    'SMTP_IN_MESSAGE': Intel_Where.SMTP_IN_MESSAGE,
    'SMTP_IN_RCPT_TO': Intel_Where.SMTP_IN_RCPT_TO,
    'SMTP_IN_RECEIVED_HEADER': Intel_Where.SMTP_IN_RECEIVED_HEADER,
    'SMTP_IN_REPLY_TO': Intel_Where.SMTP_IN_REPLY_TO,
    'SMTP_IN_TO': Intel_Where.SMTP_IN_TO,
    'SMTP_IN_X_ORIGINATING_IP_HEADER': Intel_Where.SMTP_IN_X_ORIGINATING_IP_HEADER,
    'SMTP_LOG': Log_ID.SMTP_LOG,
    'SMTP_MAIL_CLIENT': Software_Type.SMTP_MAIL_CLIENT,
    'SMTP_MAIL_SERVER': Software_Type.SMTP_MAIL_SERVER,
    'SMTP_Suspicious_Origination': Notice_Type.SMTP_Suspicious_Origination,
    'SMTP_WEBMAIL_SERVER': Software_Type.SMTP_WEBMAIL_SERVER,
}

builtins.globals()['ZLogging::SNMP'] = {
    'SNMP_LOG': Log_ID.SNMP_LOG,
}

builtins.globals()['ZLogging::SOCKS'] = {
    'CONNECTION': SOCKS_RequestType.CONNECTION,
    'PORT': SOCKS_RequestType.PORT,
    'RequestType': SOCKS_RequestType,
    'SOCKS_LOG': Log_ID.SOCKS_LOG,
    'UDP_ASSOCIATE': SOCKS_RequestType.UDP_ASSOCIATE,
}

builtins.globals()['ZLogging::SSH'] = {
    'SSH_CLIENT': Software_Type.SSH_CLIENT,
    'SSH_IN_SERVER_HOST_KEY': Intel_Where.SSH_IN_SERVER_HOST_KEY,
    'SSH_Interesting_Hostname_Login': Notice_Type.SSH_Interesting_Hostname_Login,
    'SSH_LOG': Log_ID.SSH_LOG,
    'SSH_Login_By_Password_Guesser': Notice_Type.SSH_Login_By_Password_Guesser,
    'SSH_Password_Guessing': Notice_Type.SSH_Password_Guessing,
    'SSH_SERVER': Software_Type.SSH_SERVER,
    'SSH_SUCCESSFUL_LOGIN': Intel_Where.SSH_SUCCESSFUL_LOGIN,
    'SSH_Watched_Country_Login': Notice_Type.SSH_Watched_Country_Login,
}

builtins.globals()['ZLogging::SSL'] = {
    'SCT_OCSP_EXT': SSL_SctSource.SCT_OCSP_EXT,
    'SCT_TLS_EXT': SSL_SctSource.SCT_TLS_EXT,
    'SCT_X509_EXT': SSL_SctSource.SCT_X509_EXT,
    'SSL_Certificate_Expired': Notice_Type.SSL_Certificate_Expired,
    'SSL_Certificate_Expires_Soon': Notice_Type.SSL_Certificate_Expires_Soon,
    'SSL_Certificate_Not_Valid_Yet': Notice_Type.SSL_Certificate_Not_Valid_Yet,
    'SSL_IN_SERVER_NAME': Intel_Where.SSL_IN_SERVER_NAME,
    'SSL_Invalid_Ocsp_Response': Notice_Type.SSL_Invalid_Ocsp_Response,
    'SSL_Invalid_Server_Cert': Notice_Type.SSL_Invalid_Server_Cert,
    'SSL_LOG': Log_ID.SSL_LOG,
    'SSL_Old_Version': Notice_Type.SSL_Old_Version,
    'SSL_Weak_Cipher': Notice_Type.SSL_Weak_Cipher,
    'SSL_Weak_Key': Notice_Type.SSL_Weak_Key,
    'SctSource': SSL_SctSource,
}

builtins.globals()['ZLogging::Scan'] = {
    'Scan_Address_Scan': Notice_Type.Scan_Address_Scan,
    'Scan_Port_Scan': Notice_Type.Scan_Port_Scan,
}

builtins.globals()['ZLogging::Signatures'] = {
    'Action': Signatures_Action,
    'SIG_ALARM': Signatures_Action.SIG_ALARM,
    'SIG_ALARM_ONCE': Signatures_Action.SIG_ALARM_ONCE,
    'SIG_ALARM_PER_ORIG': Signatures_Action.SIG_ALARM_PER_ORIG,
    'SIG_COUNT_PER_RESP': Signatures_Action.SIG_COUNT_PER_RESP,
    'SIG_FILE_BUT_NO_SCAN': Signatures_Action.SIG_FILE_BUT_NO_SCAN,
    'SIG_IGNORE': Signatures_Action.SIG_IGNORE,
    'SIG_LOG': Signatures_Action.SIG_LOG,
    'SIG_QUIET': Signatures_Action.SIG_QUIET,
    'SIG_SUMMARY': Signatures_Action.SIG_SUMMARY,
    'Signatures_Count_Signature': Notice_Type.Signatures_Count_Signature,
    'Signatures_LOG': Log_ID.Signatures_LOG,
    'Signatures_Multiple_Sig_Responders': Notice_Type.Signatures_Multiple_Sig_Responders,
    'Signatures_Multiple_Signatures': Notice_Type.Signatures_Multiple_Signatures,
    'Signatures_Sensitive_Signature': Notice_Type.Signatures_Sensitive_Signature,
    'Signatures_Signature_Summary': Notice_Type.Signatures_Signature_Summary,
}

builtins.globals()['ZLogging::Software'] = {
    'Software_LOG': Log_ID.Software_LOG,
    'Software_Software_Version_Change': Notice_Type.Software_Software_Version_Change,
    'Software_Vulnerable_Version': Notice_Type.Software_Vulnerable_Version,
    'Type': Software_Type,
    'UNKNOWN': Software_Type.UNKNOWN,
}

builtins.globals()['ZLogging::Stats'] = {
    'Stats_LOG': Log_ID.Stats_LOG,
}

builtins.globals()['ZLogging::SumStats'] = {
    'AVERAGE': SumStats_Calculation.AVERAGE,
    'Calculation': SumStats_Calculation,
    'HLL_UNIQUE': SumStats_Calculation.HLL_UNIQUE,
    'LAST': SumStats_Calculation.LAST,
    'MAX': SumStats_Calculation.MAX,
    'MIN': SumStats_Calculation.MIN,
    'PLACEHOLDER': SumStats_Calculation.PLACEHOLDER,
    'SAMPLE': SumStats_Calculation.SAMPLE,
    'STD_DEV': SumStats_Calculation.STD_DEV,
    'SUM': SumStats_Calculation.SUM,
    'TOPK': SumStats_Calculation.TOPK,
    'UNIQUE': SumStats_Calculation.UNIQUE,
    'VARIANCE': SumStats_Calculation.VARIANCE,
}

builtins.globals()['ZLogging::Supervisor'] = {
    'ClusterRole': Supervisor_ClusterRole,
    'LOGGER': Supervisor_ClusterRole.LOGGER,
    'MANAGER': Supervisor_ClusterRole.MANAGER,
    'NONE': Supervisor_ClusterRole.NONE,
    'PROXY': Supervisor_ClusterRole.PROXY,
    'WORKER': Supervisor_ClusterRole.WORKER,
}

builtins.globals()['ZLogging::Syslog'] = {
    'Syslog_LOG': Log_ID.Syslog_LOG,
}

builtins.globals()['ZLogging::TeamCymruMalwareHashRegistry'] = {
    'TeamCymruMalwareHashRegistry_Match': Notice_Type.TeamCymruMalwareHashRegistry_Match,
}

builtins.globals()['ZLogging::Telemetry'] = {
    'DOUBLE_COUNTER': Telemetry_MetricType.DOUBLE_COUNTER,
    'DOUBLE_GAUGE': Telemetry_MetricType.DOUBLE_GAUGE,
    'DOUBLE_HISTOGRAM': Telemetry_MetricType.DOUBLE_HISTOGRAM,
    'INT_COUNTER': Telemetry_MetricType.INT_COUNTER,
    'INT_GAUGE': Telemetry_MetricType.INT_GAUGE,
    'INT_HISTOGRAM': Telemetry_MetricType.INT_HISTOGRAM,
    'MetricType': Telemetry_MetricType,
    'Telemetry_LOG': Log_ID.Telemetry_LOG,
    'Telemetry_LOG_HISTOGRAM': Log_ID.Telemetry_LOG_HISTOGRAM,
}

builtins.globals()['ZLogging::Traceroute'] = {
    'Traceroute_Detected': Notice_Type.Traceroute_Detected,
    'Traceroute_LOG': Log_ID.Traceroute_LOG,
}

builtins.globals()['ZLogging::Tunnel'] = {
    'AYIYA': Tunnel_Type.AYIYA,
    'Action': Tunnel_Action,
    'CLOSE': Tunnel_Action.CLOSE,
    'DISCOVER': Tunnel_Action.DISCOVER,
    'EXPIRE': Tunnel_Action.EXPIRE,
    'GENEVE': Tunnel_Type.GENEVE,
    'GRE': Tunnel_Type.GRE,
    'GTPv1': Tunnel_Type.GTPv1,
    'HTTP': Tunnel_Type.HTTP,
    'IP': Tunnel_Type.IP,
    'NONE': Tunnel_Type.NONE,
    'SOCKS': Tunnel_Type.SOCKS,
    'TEREDO': Tunnel_Type.TEREDO,
    'Tunnel_LOG': Log_ID.Tunnel_LOG,
    'Type': Tunnel_Type,
    'VXLAN': Tunnel_Type.VXLAN,
}

builtins.globals()['ZLogging::UnknownProtocol'] = {
    'UnknownProtocol_LOG': Log_ID.UnknownProtocol_LOG,
}

builtins.globals()['ZLogging::Weird'] = {
    'ACTION_IGNORE': Weird_Action.ACTION_IGNORE,
    'ACTION_LOG': Weird_Action.ACTION_LOG,
    'ACTION_LOG_ONCE': Weird_Action.ACTION_LOG_ONCE,
    'ACTION_LOG_PER_CONN': Weird_Action.ACTION_LOG_PER_CONN,
    'ACTION_LOG_PER_ORIG': Weird_Action.ACTION_LOG_PER_ORIG,
    'ACTION_NOTICE': Weird_Action.ACTION_NOTICE,
    'ACTION_NOTICE_ONCE': Weird_Action.ACTION_NOTICE_ONCE,
    'ACTION_NOTICE_PER_CONN': Weird_Action.ACTION_NOTICE_PER_CONN,
    'ACTION_NOTICE_PER_ORIG': Weird_Action.ACTION_NOTICE_PER_ORIG,
    'ACTION_UNSPECIFIED': Weird_Action.ACTION_UNSPECIFIED,
    'Action': Weird_Action,
    'Weird_Activity': Notice_Type.Weird_Activity,
    'Weird_LOG': Log_ID.Weird_LOG,
}

builtins.globals()['ZLogging::WeirdStats'] = {
    'WeirdStats_LOG': Log_ID.WeirdStats_LOG,
}

builtins.globals()['ZLogging::X509'] = {
    'X509_IN_CERT': Intel_Where.X509_IN_CERT,
    'X509_LOG': Log_ID.X509_LOG,
}

builtins.globals()['ZLogging::ZeekygenExample'] = {
    'FIVE': ZeekygenExample_SimpleEnum.FIVE,
    'FOUR': ZeekygenExample_SimpleEnum.FOUR,
    'ONE': ZeekygenExample_SimpleEnum.ONE,
    'SimpleEnum': ZeekygenExample_SimpleEnum,
    'THREE': ZeekygenExample_SimpleEnum.THREE,
    'TWO': ZeekygenExample_SimpleEnum.TWO,
    'ZeekygenExample_LOG': Log_ID.ZeekygenExample_LOG,
    'ZeekygenExample_Zeekygen_Four': Notice_Type.ZeekygenExample_Zeekygen_Four,
    'ZeekygenExample_Zeekygen_One': Notice_Type.ZeekygenExample_Zeekygen_One,
    'ZeekygenExample_Zeekygen_Three': Notice_Type.ZeekygenExample_Zeekygen_Three,
    'ZeekygenExample_Zeekygen_Two': Notice_Type.ZeekygenExample_Zeekygen_Two,
}

builtins.globals()['ZLogging::mysql'] = {
    'mysql_LOG': Log_ID.mysql_LOG,
}

builtins.globals()['ZLogging::spicy'] = {
    'AddressFamily': spicy_AddressFamily,
    'AddressFamily_IPv4': spicy_AddressFamily.AddressFamily_IPv4,
    'AddressFamily_IPv6': spicy_AddressFamily.AddressFamily_IPv6,
    'AddressFamily_Undef': spicy_AddressFamily.AddressFamily_Undef,
    'BitOrder': spicy_BitOrder,
    'BitOrder_LSB0': spicy_BitOrder.BitOrder_LSB0,
    'BitOrder_MSB0': spicy_BitOrder.BitOrder_MSB0,
    'BitOrder_Undef': spicy_BitOrder.BitOrder_Undef,
    'ByteOrder': spicy_ByteOrder,
    'ByteOrder_Big': spicy_ByteOrder.ByteOrder_Big,
    'ByteOrder_Host': spicy_ByteOrder.ByteOrder_Host,
    'ByteOrder_Little': spicy_ByteOrder.ByteOrder_Little,
    'ByteOrder_Network': spicy_ByteOrder.ByteOrder_Network,
    'ByteOrder_Undef': spicy_ByteOrder.ByteOrder_Undef,
    'Charset': spicy_Charset,
    'Charset_ASCII': spicy_Charset.Charset_ASCII,
    'Charset_UTF16BE': spicy_Charset.Charset_UTF16BE,
    'Charset_UTF16LE': spicy_Charset.Charset_UTF16LE,
    'Charset_UTF8': spicy_Charset.Charset_UTF8,
    'Charset_Undef': spicy_Charset.Charset_Undef,
    'DecodeErrorStrategy': spicy_DecodeErrorStrategy,
    'DecodeErrorStrategy_IGNORE': spicy_DecodeErrorStrategy.DecodeErrorStrategy_IGNORE,
    'DecodeErrorStrategy_REPLACE': spicy_DecodeErrorStrategy.DecodeErrorStrategy_REPLACE,
    'DecodeErrorStrategy_STRICT': spicy_DecodeErrorStrategy.DecodeErrorStrategy_STRICT,
    'DecodeErrorStrategy_Undef': spicy_DecodeErrorStrategy.DecodeErrorStrategy_Undef,
    'Direction': spicy_Direction,
    'Direction_Backward': spicy_Direction.Direction_Backward,
    'Direction_Forward': spicy_Direction.Direction_Forward,
    'Direction_Undef': spicy_Direction.Direction_Undef,
    'Protocol': spicy_Protocol,
    'Protocol_ICMP': spicy_Protocol.Protocol_ICMP,
    'Protocol_TCP': spicy_Protocol.Protocol_TCP,
    'Protocol_UDP': spicy_Protocol.Protocol_UDP,
    'Protocol_Undef': spicy_Protocol.Protocol_Undef,
    'RealType': spicy_RealType,
    'RealType_IEEE754_Double': spicy_RealType.RealType_IEEE754_Double,
    'RealType_IEEE754_Single': spicy_RealType.RealType_IEEE754_Single,
    'RealType_Undef': spicy_RealType.RealType_Undef,
    'ReassemblerPolicy': spicy_ReassemblerPolicy,
    'ReassemblerPolicy_First': spicy_ReassemblerPolicy.ReassemblerPolicy_First,
    'ReassemblerPolicy_Undef': spicy_ReassemblerPolicy.ReassemblerPolicy_Undef,
    'Side': spicy_Side,
    'Side_Both': spicy_Side.Side_Both,
    'Side_Left': spicy_Side.Side_Left,
    'Side_Right': spicy_Side.Side_Right,
    'Side_Undef': spicy_Side.Side_Undef,
}

builtins.globals()['ZLogging::zeek'] = {
    'ALL_HOSTS': zeek_Host.ALL_HOSTS,
    'BIDIRECTIONAL': zeek_Direction.BIDIRECTIONAL,
    'Direction': zeek_Direction,
    'Host': zeek_Host,
    'INBOUND': zeek_Direction.INBOUND,
    'IPAddrAnonymization': zeek_IPAddrAnonymization,
    'IPAddrAnonymizationClass': zeek_IPAddrAnonymizationClass,
    'KEEP_ORIG_ADDR': zeek_IPAddrAnonymization.KEEP_ORIG_ADDR,
    'L3_ARP': zeek_layer3_proto.L3_ARP,
    'L3_IPV4': zeek_layer3_proto.L3_IPV4,
    'L3_IPV6': zeek_layer3_proto.L3_IPV6,
    'L3_UNKNOWN': zeek_layer3_proto.L3_UNKNOWN,
    'LINK_ETHERNET': zeek_link_encap.LINK_ETHERNET,
    'LINK_UNKNOWN': zeek_link_encap.LINK_UNKNOWN,
    'LOCAL_HOSTS': zeek_Host.LOCAL_HOSTS,
    'NO_DIRECTION': zeek_Direction.NO_DIRECTION,
    'NO_HOSTS': zeek_Host.NO_HOSTS,
    'None': zeek_PcapFilterID['None'],  # type: ignore[misc]
    'ORIG_ADDR': zeek_IPAddrAnonymizationClass.ORIG_ADDR,
    'OTHER_ADDR': zeek_IPAddrAnonymizationClass.OTHER_ADDR,
    'OUTBOUND': zeek_Direction.OUTBOUND,
    'PKT_PROFILE_MODE_BYTES': zeek_pkt_profile_modes.PKT_PROFILE_MODE_BYTES,
    'PKT_PROFILE_MODE_NONE': zeek_pkt_profile_modes.PKT_PROFILE_MODE_NONE,
    'PKT_PROFILE_MODE_PKTS': zeek_pkt_profile_modes.PKT_PROFILE_MODE_PKTS,
    'PKT_PROFILE_MODE_SECS': zeek_pkt_profile_modes.PKT_PROFILE_MODE_SECS,
    'PREFIX_PRESERVING_A50': zeek_IPAddrAnonymization.PREFIX_PRESERVING_A50,
    'PREFIX_PRESERVING_MD5': zeek_IPAddrAnonymization.PREFIX_PRESERVING_MD5,
    'PcapFilterID': zeek_PcapFilterID,
    'RANDOM_MD5': zeek_IPAddrAnonymization.RANDOM_MD5,
    'REMOTE_HOSTS': zeek_Host.REMOTE_HOSTS,
    'RESP_ADDR': zeek_IPAddrAnonymizationClass.RESP_ADDR,
    'RPC_AUTH_ERROR': zeek_rpc_status.RPC_AUTH_ERROR,
    'RPC_GARBAGE_ARGS': zeek_rpc_status.RPC_GARBAGE_ARGS,
    'RPC_PROC_UNAVAIL': zeek_rpc_status.RPC_PROC_UNAVAIL,
    'RPC_PROG_MISMATCH': zeek_rpc_status.RPC_PROG_MISMATCH,
    'RPC_PROG_UNAVAIL': zeek_rpc_status.RPC_PROG_UNAVAIL,
    'RPC_SUCCESS': zeek_rpc_status.RPC_SUCCESS,
    'RPC_SYSTEM_ERR': zeek_rpc_status.RPC_SYSTEM_ERR,
    'RPC_TIMEOUT': zeek_rpc_status.RPC_TIMEOUT,
    'RPC_UNKNOWN_ERROR': zeek_rpc_status.RPC_UNKNOWN_ERROR,
    'RPC_VERS_MISMATCH': zeek_rpc_status.RPC_VERS_MISMATCH,
    'SEQUENTIALLY_NUMBERED': zeek_IPAddrAnonymization.SEQUENTIALLY_NUMBERED,
    'TABLE_ELEMENT_CHANGED': zeek_TableChange.TABLE_ELEMENT_CHANGED,
    'TABLE_ELEMENT_EXPIRED': zeek_TableChange.TABLE_ELEMENT_EXPIRED,
    'TABLE_ELEMENT_NEW': zeek_TableChange.TABLE_ELEMENT_NEW,
    'TABLE_ELEMENT_REMOVED': zeek_TableChange.TABLE_ELEMENT_REMOVED,
    'TableChange': zeek_TableChange,
    'icmp': zeek_transport_proto.icmp,
    'layer3_proto': zeek_layer3_proto,
    'link_encap': zeek_link_encap,
    'pkt_profile_modes': zeek_pkt_profile_modes,
    'rpc_status': zeek_rpc_status,
    'tcp': zeek_transport_proto.tcp,
    'transport_proto': zeek_transport_proto,
    'udp': zeek_transport_proto.udp,
    'unknown_transport': zeek_transport_proto.unknown_transport,
}


def globals(*namespaces: 'str', bare: 'bool' = False) -> 'dict[str, Enum]':  # pylint: disable=redefined-builtin
    """Generate Bro/Zeek ``enum`` namespace.

    Args:
        *namespaces: Namespaces to be loaded.
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Returns:
        Global enum namespace.

    Warns:
        BroDeprecationWarning: If ``bro`` namespace used.

    Raises:
        :exc:`ValueError`: If ``namespace`` is not defined.

    Note:
        For back-port compatibility, the ``bro`` namespace is an alias of the
        ``zeek`` namespace.

    """
    if bare:
        enum_data = {}  # type: dict[str, Enum]
    else:
        enum_data = builtins.globals()['ZLogging::zeek'].copy()
    for namespace in namespaces:
        if namespace == 'bro':
            warnings.warn("Use of 'bro' is deprecated. "
                          "Please use 'zeek' instead.", BroDeprecationWarning)
            namespace = 'zeek'

        enum_dict = builtins.globals().get('ZLogging::%s' % namespace)  # pylint: disable=consider-using-f-string
        if enum_dict is None:
            raise ValueError('undefined namespace: %s' % namespace)  # pylint: disable=consider-using-f-string
        enum_data.update(enum_dict)
    return enum_data
