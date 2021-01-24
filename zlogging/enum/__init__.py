# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Bro/Zeek enum namespace."""

import warnings
from typing import TYPE_CHECKING

from zlogging._exc import BroDeprecationWarning
from zlogging.enum.Broker import BackendType as Broker_BackendType
from zlogging.enum.Broker import DataType as Broker_DataType
from zlogging.enum.Broker import ErrorCode as Broker_ErrorCode
from zlogging.enum.Broker import PeerStatus as Broker_PeerStatus
from zlogging.enum.Broker import QueryStatus as Broker_QueryStatus
from zlogging.enum.Broker import Type as Broker_Type
from zlogging.enum.Cluster import NodeType as Cluster_NodeType
from zlogging.enum.DCE_RPC import IfID as DCE_RPC_IfID
from zlogging.enum.DCE_RPC import PType as DCE_RPC_PType
from zlogging.enum.HTTP import Tags as HTTP_Tags
from zlogging.enum.Input import Event as Input_Event
from zlogging.enum.Input import Mode as Input_Mode
from zlogging.enum.Input import Reader as Input_Reader
from zlogging.enum.Intel import Type as Intel_Type
from zlogging.enum.Intel import Where as Intel_Where
from zlogging.enum.JSON import TimestampFormat as JSON_TimestampFormat
from zlogging.enum.Known import ModbusDeviceType as Known_ModbusDeviceType
from zlogging.enum.LoadBalancing import Method as LoadBalancing_Method
from zlogging.enum.Log import ID as Log_ID
from zlogging.enum.Log import PrintLogType as Log_PrintLogType
from zlogging.enum.Log import Writer as Log_Writer
from zlogging.enum.MOUNT3 import auth_flavor_t as MOUNT3_auth_flavor_t
from zlogging.enum.MOUNT3 import proc_t as MOUNT3_proc_t
from zlogging.enum.MOUNT3 import status_t as MOUNT3_status_t
from zlogging.enum.MQTT import SubUnsub as MQTT_SubUnsub
from zlogging.enum.NFS3 import createmode_t as NFS3_createmode_t
from zlogging.enum.NFS3 import file_type_t as NFS3_file_type_t
from zlogging.enum.NFS3 import proc_t as NFS3_proc_t
from zlogging.enum.NFS3 import stable_how_t as NFS3_stable_how_t
from zlogging.enum.NFS3 import status_t as NFS3_status_t
from zlogging.enum.NFS3 import time_how_t as NFS3_time_how_t
from zlogging.enum.NetControl import CatchReleaseActions as NetControl_CatchReleaseActions
from zlogging.enum.NetControl import EntityType as NetControl_EntityType
from zlogging.enum.NetControl import InfoCategory as NetControl_InfoCategory
from zlogging.enum.NetControl import InfoState as NetControl_InfoState
from zlogging.enum.NetControl import RuleType as NetControl_RuleType
from zlogging.enum.NetControl import TargetType as NetControl_TargetType
from zlogging.enum.Notice import Action as Notice_Action
from zlogging.enum.Notice import Type as Notice_Type
from zlogging.enum.OpenFlow import Plugin as OpenFlow_Plugin
from zlogging.enum.OpenFlow import ofp_action_type as OpenFlow_ofp_action_type
from zlogging.enum.OpenFlow import ofp_config_flags as OpenFlow_ofp_config_flags
from zlogging.enum.OpenFlow import ofp_flow_mod_command as OpenFlow_ofp_flow_mod_command
from zlogging.enum.ProtocolDetector import dir as ProtocolDetector_dir
from zlogging.enum.Reporter import Level as Reporter_Level
from zlogging.enum.SMB import Action as SMB_Action
from zlogging.enum.SOCKS import RequestType as SOCKS_RequestType
from zlogging.enum.SSL import SctSource as SSL_SctSource
from zlogging.enum.Signatures import Action as Signatures_Action
from zlogging.enum.Software import Type as Software_Type
from zlogging.enum.SumStats import Calculation as SumStats_Calculation
from zlogging.enum.Supervisor import ClusterRole as Supervisor_ClusterRole
from zlogging.enum.Tunnel import Action as Tunnel_Action
from zlogging.enum.Tunnel import Type as Tunnel_Type
from zlogging.enum.Weird import Action as Weird_Action
from zlogging.enum.ZeekygenExample import SimpleEnum as ZeekygenExample_SimpleEnum
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

__all__ = ['globals']

if TYPE_CHECKING:
    from enum import Enum
    from typing import Dict

_enum_Barnyard2 = {
    'LOG': Log_ID['Barnyard2__LOG'],
}

_enum_Broker = {
    'ADDR': Broker_DataType['ADDR'],
    'BACKEND_FAILURE': Broker_ErrorCode['BACKEND_FAILURE'],
    'BOOL': Broker_DataType['BOOL'],
    'BackendType': Broker_BackendType,
    'CAF_ERROR': Broker_ErrorCode['CAF_ERROR'],
    'CANNOT_OPEN_FILE': Broker_ErrorCode['CANNOT_OPEN_FILE'],
    'CANNOT_WRITE_FILE': Broker_ErrorCode['CANNOT_WRITE_FILE'],
    'CONNECTED': Broker_PeerStatus['CONNECTED'],
    'CONNECTING': Broker_PeerStatus['CONNECTING'],
    'COUNT': Broker_DataType['COUNT'],
    'DISCONNECTED': Broker_PeerStatus['DISCONNECTED'],
    'DOUBLE': Broker_DataType['DOUBLE'],
    'DataType': Broker_DataType,
    'END_OF_FILE': Broker_ErrorCode['END_OF_FILE'],
    'ENUM': Broker_DataType['ENUM'],
    'ERROR': Broker_Type['ERROR'],
    'ErrorCode': Broker_ErrorCode,
    'FAILURE': Broker_QueryStatus['FAILURE'],
    'INITIALIZING': Broker_PeerStatus['INITIALIZING'],
    'INT': Broker_DataType['INT'],
    'INTERVAL': Broker_DataType['INTERVAL'],
    'INVALID_DATA': Broker_ErrorCode['INVALID_DATA'],
    'INVALID_STATUS': Broker_ErrorCode['INVALID_STATUS'],
    'INVALID_TAG': Broker_ErrorCode['INVALID_TAG'],
    'INVALID_TOPIC_KEY': Broker_ErrorCode['INVALID_TOPIC_KEY'],
    'LOG': Log_ID['Broker__LOG'],
    'MASTER_EXISTS': Broker_ErrorCode['MASTER_EXISTS'],
    'MEMORY': Broker_BackendType['MEMORY'],
    'NONE': Broker_DataType['NONE'],
    'NO_ERROR': Broker_ErrorCode['NO_ERROR'],
    'NO_SUCH_KEY': Broker_ErrorCode['NO_SUCH_KEY'],
    'NO_SUCH_MASTER': Broker_ErrorCode['NO_SUCH_MASTER'],
    'PEERED': Broker_PeerStatus['PEERED'],
    'PEER_DISCONNECT_DURING_HANDSHAKE': Broker_ErrorCode['PEER_DISCONNECT_DURING_HANDSHAKE'],
    'PEER_INCOMPATIBLE': Broker_ErrorCode['PEER_INCOMPATIBLE'],
    'PEER_INVALID': Broker_ErrorCode['PEER_INVALID'],
    'PEER_TIMEOUT': Broker_ErrorCode['PEER_TIMEOUT'],
    'PEER_UNAVAILABLE': Broker_ErrorCode['PEER_UNAVAILABLE'],
    'PORT': Broker_DataType['PORT'],
    'PeerStatus': Broker_PeerStatus,
    'QueryStatus': Broker_QueryStatus,
    'RECONNECTING': Broker_PeerStatus['RECONNECTING'],
    'REQUEST_TIMEOUT': Broker_ErrorCode['REQUEST_TIMEOUT'],
    'ROCKSDB': Broker_BackendType['ROCKSDB'],
    'SET': Broker_DataType['SET'],
    'SQLITE': Broker_BackendType['SQLITE'],
    'STALE_DATA': Broker_ErrorCode['STALE_DATA'],
    'STATUS': Broker_Type['STATUS'],
    'STRING': Broker_DataType['STRING'],
    'SUBNET': Broker_DataType['SUBNET'],
    'SUCCESS': Broker_QueryStatus['SUCCESS'],
    'TABLE': Broker_DataType['TABLE'],
    'TIME': Broker_DataType['TIME'],
    'TYPE_CLASH': Broker_ErrorCode['TYPE_CLASH'],
    'Type': Broker_Type,
    'UNSPECIFIED': Broker_ErrorCode['UNSPECIFIED'],
    'VECTOR': Broker_DataType['VECTOR'],
}

_enum_CaptureLoss = {
    'LOG': Log_ID['CaptureLoss__LOG'],
    'Too_Much_Loss': Notice_Type['CaptureLoss__Too_Much_Loss'],
}

_enum_Cluster = {
    'CONTROL': Cluster_NodeType['CONTROL'],
    'LOG': Log_ID['Cluster__LOG'],
    'LOGGER': Cluster_NodeType['LOGGER'],
    'MANAGER': Cluster_NodeType['MANAGER'],
    'NONE': Cluster_NodeType['NONE'],
    'NodeType': Cluster_NodeType,
    'PROXY': Cluster_NodeType['PROXY'],
    'TIME_MACHINE': Cluster_NodeType['TIME_MACHINE'],
    'WORKER': Cluster_NodeType['WORKER'],
}

_enum_Config = {
    'LOG': Log_ID['Config__LOG'],
}

_enum_Conn = {
    'Content_Gap': Notice_Type['Conn__Content_Gap'],
    'IN_ORIG': Intel_Where['Conn__IN_ORIG'],
    'IN_RESP': Intel_Where['Conn__IN_RESP'],
    'LOG': Log_ID['Conn__LOG'],
    'Retransmission_Inconsistency': Notice_Type['Conn__Retransmission_Inconsistency'],
}

_enum_DCE_RPC = {
    'ACK': DCE_RPC_PType['ACK'],
    'ALTER_CONTEXT': DCE_RPC_PType['ALTER_CONTEXT'],
    'ALTER_CONTEXT_RESP': DCE_RPC_PType['ALTER_CONTEXT_RESP'],
    'AUTH3': DCE_RPC_PType['AUTH3'],
    'BIND': DCE_RPC_PType['BIND'],
    'BIND_ACK': DCE_RPC_PType['BIND_ACK'],
    'BIND_NAK': DCE_RPC_PType['BIND_NAK'],
    'CANCEL_ACK': DCE_RPC_PType['CANCEL_ACK'],
    'CL_CANCEL': DCE_RPC_PType['CL_CANCEL'],
    'CO_CANCEL': DCE_RPC_PType['CO_CANCEL'],
    'FACK': DCE_RPC_PType['FACK'],
    'FAULT': DCE_RPC_PType['FAULT'],
    'ISCMActivator': DCE_RPC_IfID['ISCMActivator'],
    'IfID': DCE_RPC_IfID,
    'LOG': Log_ID['DCE_RPC__LOG'],
    'NOCALL': DCE_RPC_PType['NOCALL'],
    'ORPHANED': DCE_RPC_PType['ORPHANED'],
    'PING': DCE_RPC_PType['PING'],
    'PType': DCE_RPC_PType,
    'REJECT': DCE_RPC_PType['REJECT'],
    'REQUEST': DCE_RPC_PType['REQUEST'],
    'RESPONSE': DCE_RPC_PType['RESPONSE'],
    'RTS': DCE_RPC_PType['RTS'],
    'SHUTDOWN': DCE_RPC_PType['SHUTDOWN'],
    'WORKING': DCE_RPC_PType['WORKING'],
    'drs': DCE_RPC_IfID['drs'],
    'epmapper': DCE_RPC_IfID['epmapper'],
    'lsa_ds': DCE_RPC_IfID['lsa_ds'],
    'lsarpc': DCE_RPC_IfID['lsarpc'],
    'mgmt': DCE_RPC_IfID['mgmt'],
    'netlogon': DCE_RPC_IfID['netlogon'],
    'oxid': DCE_RPC_IfID['oxid'],
    'samr': DCE_RPC_IfID['samr'],
    'spoolss': DCE_RPC_IfID['spoolss'],
    'srvsvc': DCE_RPC_IfID['srvsvc'],
    'unknown_if': DCE_RPC_IfID['unknown_if'],
    'winspipe': DCE_RPC_IfID['winspipe'],
    'wkssvc': DCE_RPC_IfID['wkssvc'],
}

_enum_DHCP = {
    'CLIENT': Software_Type['DHCP__CLIENT'],
    'LOG': Log_ID['DHCP__LOG'],
    'SERVER': Software_Type['DHCP__SERVER'],
}

_enum_DNP3 = {
    'LOG': Log_ID['DNP3__LOG'],
}

_enum_DNS = {
    'External_Name': Notice_Type['DNS__External_Name'],
    'IN_REQUEST': Intel_Where['DNS__IN_REQUEST'],
    'IN_RESPONSE': Intel_Where['DNS__IN_RESPONSE'],
    'LOG': Log_ID['DNS__LOG'],
}

_enum_DPD = {
    'LOG': Log_ID['DPD__LOG'],
}

_enum_FTP = {
    'Bruteforcing': Notice_Type['FTP__Bruteforcing'],
    'CLIENT': Software_Type['FTP__CLIENT'],
    'LOG': Log_ID['FTP__LOG'],
    'SERVER': Software_Type['FTP__SERVER'],
    'Site_Exec_Success': Notice_Type['FTP__Site_Exec_Success'],
}

_enum_Files = {
    'IN_HASH': Intel_Where['Files__IN_HASH'],
    'IN_NAME': Intel_Where['Files__IN_NAME'],
    'LOG': Log_ID['Files__LOG'],
}

_enum_HTTP = {
    'APPSERVER': Software_Type['HTTP__APPSERVER'],
    'BROWSER': Software_Type['HTTP__BROWSER'],
    'BROWSER_PLUGIN': Software_Type['HTTP__BROWSER_PLUGIN'],
    'COOKIE_SQLI': HTTP_Tags['COOKIE_SQLI'],
    'EMPTY': HTTP_Tags['EMPTY'],
    'IN_HOST_HEADER': Intel_Where['HTTP__IN_HOST_HEADER'],
    'IN_REFERRER_HEADER': Intel_Where['HTTP__IN_REFERRER_HEADER'],
    'IN_URL': Intel_Where['HTTP__IN_URL'],
    'IN_USER_AGENT_HEADER': Intel_Where['HTTP__IN_USER_AGENT_HEADER'],
    'IN_X_FORWARDED_FOR_HEADER': Intel_Where['HTTP__IN_X_FORWARDED_FOR_HEADER'],
    'LOG': Log_ID['HTTP__LOG'],
    'POST_SQLI': HTTP_Tags['POST_SQLI'],
    'SERVER': Software_Type['HTTP__SERVER'],
    'SQL_Injection_Attacker': Notice_Type['HTTP__SQL_Injection_Attacker'],
    'SQL_Injection_Victim': Notice_Type['HTTP__SQL_Injection_Victim'],
    'Tags': HTTP_Tags,
    'URI_SQLI': HTTP_Tags['URI_SQLI'],
    'WEB_APPLICATION': Software_Type['HTTP__WEB_APPLICATION'],
}

_enum_Heartbleed = {
    'SSL_Heartbeat_Attack': Notice_Type['Heartbleed__SSL_Heartbeat_Attack'],
    'SSL_Heartbeat_Attack_Success': Notice_Type['Heartbleed__SSL_Heartbeat_Attack_Success'],
    'SSL_Heartbeat_Many_Requests': Notice_Type['Heartbleed__SSL_Heartbeat_Many_Requests'],
    'SSL_Heartbeat_Odd_Length': Notice_Type['Heartbleed__SSL_Heartbeat_Odd_Length'],
}

_enum_IRC = {
    'LOG': Log_ID['IRC__LOG'],
}

_enum_Input = {
    'EVENT_CHANGED': Input_Event['EVENT_CHANGED'],
    'EVENT_NEW': Input_Event['EVENT_NEW'],
    'EVENT_REMOVED': Input_Event['EVENT_REMOVED'],
    'Event': Input_Event,
    'MANUAL': Input_Mode['MANUAL'],
    'Mode': Input_Mode,
    'READER_ASCII': Input_Reader['READER_ASCII'],
    'READER_BENCHMARK': Input_Reader['READER_BENCHMARK'],
    'READER_BINARY': Input_Reader['READER_BINARY'],
    'READER_CONFIG': Input_Reader['READER_CONFIG'],
    'READER_RAW': Input_Reader['READER_RAW'],
    'READER_SQLITE': Input_Reader['READER_SQLITE'],
    'REREAD': Input_Mode['REREAD'],
    'Reader': Input_Reader,
    'STREAM': Input_Mode['STREAM'],
}

_enum_Intel = {
    'ADDR': Intel_Type['ADDR'],
    'CERT_HASH': Intel_Type['CERT_HASH'],
    'DOMAIN': Intel_Type['DOMAIN'],
    'EMAIL': Intel_Type['EMAIL'],
    'FILE_HASH': Intel_Type['FILE_HASH'],
    'FILE_NAME': Intel_Type['FILE_NAME'],
    'IN_ANYWHERE': Intel_Where['IN_ANYWHERE'],
    'LOG': Log_ID['Intel__LOG'],
    'Notice': Notice_Type['Intel__Notice'],
    'PUBKEY_HASH': Intel_Type['PUBKEY_HASH'],
    'SOFTWARE': Intel_Type['SOFTWARE'],
    'SUBNET': Intel_Type['SUBNET'],
    'Type': Intel_Type,
    'URL': Intel_Type['URL'],
    'USER_NAME': Intel_Type['USER_NAME'],
    'Where': Intel_Where,
}

_enum_JSON = {
    'TS_EPOCH': JSON_TimestampFormat['TS_EPOCH'],
    'TS_ISO8601': JSON_TimestampFormat['TS_ISO8601'],
    'TS_MILLIS': JSON_TimestampFormat['TS_MILLIS'],
    'TimestampFormat': JSON_TimestampFormat,
}

_enum_KRB = {
    'LOG': Log_ID['KRB__LOG'],
}

_enum_Known = {
    'CERTS_LOG': Log_ID['Known__CERTS_LOG'],
    'HOSTS_LOG': Log_ID['Known__HOSTS_LOG'],
    'MODBUS_LOG': Log_ID['Known__MODBUS_LOG'],
    'MODBUS_MASTER': Known_ModbusDeviceType['MODBUS_MASTER'],
    'MODBUS_SLAVE': Known_ModbusDeviceType['MODBUS_SLAVE'],
    'ModbusDeviceType': Known_ModbusDeviceType,
    'SERVICES_LOG': Log_ID['Known__SERVICES_LOG'],
}

_enum_LoadBalancing = {
    'AUTO_BPF': LoadBalancing_Method['AUTO_BPF'],
    'Method': LoadBalancing_Method,
}

_enum_LoadedScripts = {
    'LOG': Log_ID['LoadedScripts__LOG'],
}

_enum_Log = {
    'ID': Log_ID,
    'PRINTLOG': Log_ID['PRINTLOG'],
    'PrintLogType': Log_PrintLogType,
    'REDIRECT_ALL': Log_PrintLogType['REDIRECT_ALL'],
    'REDIRECT_NONE': Log_PrintLogType['REDIRECT_NONE'],
    'REDIRECT_STDOUT': Log_PrintLogType['REDIRECT_STDOUT'],
    'UNKNOWN': Log_ID['UNKNOWN'],
    'WRITER_ASCII': Log_Writer['WRITER_ASCII'],
    'WRITER_NONE': Log_Writer['WRITER_NONE'],
    'WRITER_SQLITE': Log_Writer['WRITER_SQLITE'],
    'Writer': Log_Writer,
}

_enum_MOUNT3 = {
    'AUTH_DES': MOUNT3_auth_flavor_t['AUTH_DES'],
    'AUTH_NULL': MOUNT3_auth_flavor_t['AUTH_NULL'],
    'AUTH_SHORT': MOUNT3_auth_flavor_t['AUTH_SHORT'],
    'AUTH_UNIX': MOUNT3_auth_flavor_t['AUTH_UNIX'],
    'MNT3ERR_ACCES': MOUNT3_status_t['MNT3ERR_ACCES'],
    'MNT3ERR_INVAL': MOUNT3_status_t['MNT3ERR_INVAL'],
    'MNT3ERR_IO': MOUNT3_status_t['MNT3ERR_IO'],
    'MNT3ERR_NAMETOOLONG': MOUNT3_status_t['MNT3ERR_NAMETOOLONG'],
    'MNT3ERR_NOENT': MOUNT3_status_t['MNT3ERR_NOENT'],
    'MNT3ERR_NOTDIR': MOUNT3_status_t['MNT3ERR_NOTDIR'],
    'MNT3ERR_NOTSUPP': MOUNT3_status_t['MNT3ERR_NOTSUPP'],
    'MNT3ERR_PERM': MOUNT3_status_t['MNT3ERR_PERM'],
    'MNT3ERR_SERVERFAULT': MOUNT3_status_t['MNT3ERR_SERVERFAULT'],
    'MNT3_OK': MOUNT3_status_t['MNT3_OK'],
    'MOUNT3ERR_UNKNOWN': MOUNT3_status_t['MOUNT3ERR_UNKNOWN'],
    'PROC_DUMP': MOUNT3_proc_t['PROC_DUMP'],
    'PROC_END_OF_PROCS': MOUNT3_proc_t['PROC_END_OF_PROCS'],
    'PROC_EXPORT': MOUNT3_proc_t['PROC_EXPORT'],
    'PROC_MNT': MOUNT3_proc_t['PROC_MNT'],
    'PROC_NULL': MOUNT3_proc_t['PROC_NULL'],
    'PROC_UMNT': MOUNT3_proc_t['PROC_UMNT'],
    'PROC_UMNT_ALL': MOUNT3_proc_t['PROC_UMNT_ALL'],
    'auth_flavor_t': MOUNT3_auth_flavor_t,
    'proc_t': MOUNT3_proc_t,
    'status_t': MOUNT3_status_t,
}

_enum_MQTT = {
    'CONNECT_LOG': Log_ID['MQTT__CONNECT_LOG'],
    'PUBLISH_LOG': Log_ID['MQTT__PUBLISH_LOG'],
    'SUBSCRIBE': MQTT_SubUnsub['SUBSCRIBE'],
    'SUBSCRIBE_LOG': Log_ID['MQTT__SUBSCRIBE_LOG'],
    'SubUnsub': MQTT_SubUnsub,
    'UNSUBSCRIBE': MQTT_SubUnsub['UNSUBSCRIBE'],
}

_enum_Modbus = {
    'LOG': Log_ID['Modbus__LOG'],
    'REGISTER_CHANGE_LOG': Log_ID['Modbus__REGISTER_CHANGE_LOG'],
}

_enum_MySQL = {
    'SERVER': Software_Type['MySQL__SERVER'],
}

_enum_NFS3 = {
    'DATA_SYNC': NFS3_stable_how_t['DATA_SYNC'],
    'DONT_CHANGE': NFS3_time_how_t['DONT_CHANGE'],
    'EXCLUSIVE': NFS3_createmode_t['EXCLUSIVE'],
    'FILE_SYNC': NFS3_stable_how_t['FILE_SYNC'],
    'FTYPE_BLK': NFS3_file_type_t['FTYPE_BLK'],
    'FTYPE_CHR': NFS3_file_type_t['FTYPE_CHR'],
    'FTYPE_DIR': NFS3_file_type_t['FTYPE_DIR'],
    'FTYPE_FIFO': NFS3_file_type_t['FTYPE_FIFO'],
    'FTYPE_LNK': NFS3_file_type_t['FTYPE_LNK'],
    'FTYPE_REG': NFS3_file_type_t['FTYPE_REG'],
    'FTYPE_SOCK': NFS3_file_type_t['FTYPE_SOCK'],
    'GUARDED': NFS3_createmode_t['GUARDED'],
    'NFS3ERR_ACCES': NFS3_status_t['NFS3ERR_ACCES'],
    'NFS3ERR_BADHANDLE': NFS3_status_t['NFS3ERR_BADHANDLE'],
    'NFS3ERR_BADTYPE': NFS3_status_t['NFS3ERR_BADTYPE'],
    'NFS3ERR_BAD_COOKIE': NFS3_status_t['NFS3ERR_BAD_COOKIE'],
    'NFS3ERR_DQUOT': NFS3_status_t['NFS3ERR_DQUOT'],
    'NFS3ERR_EXIST': NFS3_status_t['NFS3ERR_EXIST'],
    'NFS3ERR_FBIG': NFS3_status_t['NFS3ERR_FBIG'],
    'NFS3ERR_INVAL': NFS3_status_t['NFS3ERR_INVAL'],
    'NFS3ERR_IO': NFS3_status_t['NFS3ERR_IO'],
    'NFS3ERR_ISDIR': NFS3_status_t['NFS3ERR_ISDIR'],
    'NFS3ERR_JUKEBOX': NFS3_status_t['NFS3ERR_JUKEBOX'],
    'NFS3ERR_MLINK': NFS3_status_t['NFS3ERR_MLINK'],
    'NFS3ERR_NAMETOOLONG': NFS3_status_t['NFS3ERR_NAMETOOLONG'],
    'NFS3ERR_NODEV': NFS3_status_t['NFS3ERR_NODEV'],
    'NFS3ERR_NOENT': NFS3_status_t['NFS3ERR_NOENT'],
    'NFS3ERR_NOSPC': NFS3_status_t['NFS3ERR_NOSPC'],
    'NFS3ERR_NOTDIR': NFS3_status_t['NFS3ERR_NOTDIR'],
    'NFS3ERR_NOTEMPTY': NFS3_status_t['NFS3ERR_NOTEMPTY'],
    'NFS3ERR_NOTSUPP': NFS3_status_t['NFS3ERR_NOTSUPP'],
    'NFS3ERR_NOT_SYNC': NFS3_status_t['NFS3ERR_NOT_SYNC'],
    'NFS3ERR_NXIO': NFS3_status_t['NFS3ERR_NXIO'],
    'NFS3ERR_OK': NFS3_status_t['NFS3ERR_OK'],
    'NFS3ERR_PERM': NFS3_status_t['NFS3ERR_PERM'],
    'NFS3ERR_REMOTE': NFS3_status_t['NFS3ERR_REMOTE'],
    'NFS3ERR_ROFS': NFS3_status_t['NFS3ERR_ROFS'],
    'NFS3ERR_SERVERFAULT': NFS3_status_t['NFS3ERR_SERVERFAULT'],
    'NFS3ERR_STALE': NFS3_status_t['NFS3ERR_STALE'],
    'NFS3ERR_TOOSMALL': NFS3_status_t['NFS3ERR_TOOSMALL'],
    'NFS3ERR_UNKNOWN': NFS3_status_t['NFS3ERR_UNKNOWN'],
    'NFS3ERR_XDEV': NFS3_status_t['NFS3ERR_XDEV'],
    'PROC_ACCESS': NFS3_proc_t['PROC_ACCESS'],
    'PROC_COMMIT': NFS3_proc_t['PROC_COMMIT'],
    'PROC_CREATE': NFS3_proc_t['PROC_CREATE'],
    'PROC_END_OF_PROCS': NFS3_proc_t['PROC_END_OF_PROCS'],
    'PROC_FSINFO': NFS3_proc_t['PROC_FSINFO'],
    'PROC_FSSTAT': NFS3_proc_t['PROC_FSSTAT'],
    'PROC_GETATTR': NFS3_proc_t['PROC_GETATTR'],
    'PROC_LINK': NFS3_proc_t['PROC_LINK'],
    'PROC_LOOKUP': NFS3_proc_t['PROC_LOOKUP'],
    'PROC_MKDIR': NFS3_proc_t['PROC_MKDIR'],
    'PROC_MKNOD': NFS3_proc_t['PROC_MKNOD'],
    'PROC_NULL': NFS3_proc_t['PROC_NULL'],
    'PROC_PATHCONF': NFS3_proc_t['PROC_PATHCONF'],
    'PROC_READ': NFS3_proc_t['PROC_READ'],
    'PROC_READDIR': NFS3_proc_t['PROC_READDIR'],
    'PROC_READDIRPLUS': NFS3_proc_t['PROC_READDIRPLUS'],
    'PROC_READLINK': NFS3_proc_t['PROC_READLINK'],
    'PROC_REMOVE': NFS3_proc_t['PROC_REMOVE'],
    'PROC_RENAME': NFS3_proc_t['PROC_RENAME'],
    'PROC_RMDIR': NFS3_proc_t['PROC_RMDIR'],
    'PROC_SETATTR': NFS3_proc_t['PROC_SETATTR'],
    'PROC_SYMLINK': NFS3_proc_t['PROC_SYMLINK'],
    'PROC_WRITE': NFS3_proc_t['PROC_WRITE'],
    'SET_TO_CLIENT_TIME': NFS3_time_how_t['SET_TO_CLIENT_TIME'],
    'SET_TO_SERVER_TIME': NFS3_time_how_t['SET_TO_SERVER_TIME'],
    'UNCHECKED': NFS3_createmode_t['UNCHECKED'],
    'UNSTABLE': NFS3_stable_how_t['UNSTABLE'],
    'createmode_t': NFS3_createmode_t,
    'file_type_t': NFS3_file_type_t,
    'proc_t': NFS3_proc_t,
    'stable_how_t': NFS3_stable_how_t,
    'status_t': NFS3_status_t,
    'time_how_t': NFS3_time_how_t,
}

_enum_NTLM = {
    'LOG': Log_ID['NTLM__LOG'],
}

_enum_NTP = {
    'LOG': Log_ID['NTP__LOG'],
}

_enum_NetControl = {
    'ADDED': NetControl_CatchReleaseActions['ADDED'],
    'ADDRESS': NetControl_EntityType['ADDRESS'],
    'CATCH_RELEASE': Log_ID['NetControl__CATCH_RELEASE'],
    'CONNECTION': NetControl_EntityType['CONNECTION'],
    'CatchReleaseActions': NetControl_CatchReleaseActions,
    'DROP': Log_ID['NetControl__DROP'],
    'DROP': NetControl_CatchReleaseActions['DROP'],
    'DROP': NetControl_RuleType['DROP'],
    'DROPPED': NetControl_CatchReleaseActions['DROPPED'],
    'ERROR': NetControl_InfoCategory['ERROR'],
    'EXISTS': NetControl_InfoState['EXISTS'],
    'EntityType': NetControl_EntityType,
    'FAILED': NetControl_InfoState['FAILED'],
    'FLOW': NetControl_EntityType['FLOW'],
    'FORGOTTEN': NetControl_CatchReleaseActions['FORGOTTEN'],
    'FORWARD': NetControl_TargetType['FORWARD'],
    'INFO': NetControl_CatchReleaseActions['INFO'],
    'InfoCategory': NetControl_InfoCategory,
    'InfoState': NetControl_InfoState,
    'LOG': Log_ID['NetControl__LOG'],
    'MAC': NetControl_EntityType['MAC'],
    'MESSAGE': NetControl_InfoCategory['MESSAGE'],
    'MODIFY': NetControl_RuleType['MODIFY'],
    'MONITOR': NetControl_TargetType['MONITOR'],
    'REDIRECT': NetControl_RuleType['REDIRECT'],
    'REMOVED': NetControl_InfoState['REMOVED'],
    'REQUESTED': NetControl_InfoState['REQUESTED'],
    'RULE': NetControl_InfoCategory['RULE'],
    'RuleType': NetControl_RuleType,
    'SEEN_AGAIN': NetControl_CatchReleaseActions['SEEN_AGAIN'],
    'SHUNT': Log_ID['NetControl__SHUNT'],
    'SUCCEEDED': NetControl_InfoState['SUCCEEDED'],
    'TIMEOUT': NetControl_InfoState['TIMEOUT'],
    'TargetType': NetControl_TargetType,
    'UNBLOCK': NetControl_CatchReleaseActions['UNBLOCK'],
    'WHITELIST': NetControl_RuleType['WHITELIST'],
}

_enum_Notice = {
    'ACTION_ADD_GEODATA': Notice_Action['ACTION_ADD_GEODATA'],
    'ACTION_ALARM': Notice_Action['ACTION_ALARM'],
    'ACTION_DROP': Notice_Action['ACTION_DROP'],
    'ACTION_EMAIL': Notice_Action['ACTION_EMAIL'],
    'ACTION_EMAIL_ADMIN': Notice_Action['ACTION_EMAIL_ADMIN'],
    'ACTION_LOG': Notice_Action['ACTION_LOG'],
    'ACTION_NONE': Notice_Action['ACTION_NONE'],
    'ACTION_PAGE': Notice_Action['ACTION_PAGE'],
    'ALARM_LOG': Log_ID['Notice__ALARM_LOG'],
    'Action': Notice_Action,
    'LOG': Log_ID['Notice__LOG'],
    'Tally': Notice_Type['Tally'],
    'Type': Notice_Type,
}

_enum_OCSP = {
    'LOG': Log_ID['OCSP__LOG'],
}

_enum_OS = {
    'WINDOWS': Software_Type['OS__WINDOWS'],
}

_enum_OpenFlow = {
    'BROKER': OpenFlow_Plugin['BROKER'],
    'INVALID': OpenFlow_Plugin['INVALID'],
    'LOG': Log_ID['OpenFlow__LOG'],
    'OFLOG': OpenFlow_Plugin['OFLOG'],
    'OFPAT_ENQUEUE': OpenFlow_ofp_action_type['OFPAT_ENQUEUE'],
    'OFPAT_OUTPUT': OpenFlow_ofp_action_type['OFPAT_OUTPUT'],
    'OFPAT_SET_DL_DST': OpenFlow_ofp_action_type['OFPAT_SET_DL_DST'],
    'OFPAT_SET_DL_SRC': OpenFlow_ofp_action_type['OFPAT_SET_DL_SRC'],
    'OFPAT_SET_NW_DST': OpenFlow_ofp_action_type['OFPAT_SET_NW_DST'],
    'OFPAT_SET_NW_SRC': OpenFlow_ofp_action_type['OFPAT_SET_NW_SRC'],
    'OFPAT_SET_NW_TOS': OpenFlow_ofp_action_type['OFPAT_SET_NW_TOS'],
    'OFPAT_SET_TP_DST': OpenFlow_ofp_action_type['OFPAT_SET_TP_DST'],
    'OFPAT_SET_TP_SRC': OpenFlow_ofp_action_type['OFPAT_SET_TP_SRC'],
    'OFPAT_SET_VLAN_PCP': OpenFlow_ofp_action_type['OFPAT_SET_VLAN_PCP'],
    'OFPAT_SET_VLAN_VID': OpenFlow_ofp_action_type['OFPAT_SET_VLAN_VID'],
    'OFPAT_STRIP_VLAN': OpenFlow_ofp_action_type['OFPAT_STRIP_VLAN'],
    'OFPAT_VENDOR': OpenFlow_ofp_action_type['OFPAT_VENDOR'],
    'OFPC_FRAG_DROP': OpenFlow_ofp_config_flags['OFPC_FRAG_DROP'],
    'OFPC_FRAG_MASK': OpenFlow_ofp_config_flags['OFPC_FRAG_MASK'],
    'OFPC_FRAG_NORMAL': OpenFlow_ofp_config_flags['OFPC_FRAG_NORMAL'],
    'OFPC_FRAG_REASM': OpenFlow_ofp_config_flags['OFPC_FRAG_REASM'],
    'OFPFC_ADD': OpenFlow_ofp_flow_mod_command['OFPFC_ADD'],
    'OFPFC_DELETE': OpenFlow_ofp_flow_mod_command['OFPFC_DELETE'],
    'OFPFC_DELETE_STRICT': OpenFlow_ofp_flow_mod_command['OFPFC_DELETE_STRICT'],
    'OFPFC_MODIFY': OpenFlow_ofp_flow_mod_command['OFPFC_MODIFY'],
    'OFPFC_MODIFY_STRICT': OpenFlow_ofp_flow_mod_command['OFPFC_MODIFY_STRICT'],
    'Plugin': OpenFlow_Plugin,
    'RYU': OpenFlow_Plugin['RYU'],
    'ofp_action_type': OpenFlow_ofp_action_type,
    'ofp_config_flags': OpenFlow_ofp_config_flags,
    'ofp_flow_mod_command': OpenFlow_ofp_flow_mod_command,
}

_enum_PE = {
    'LOG': Log_ID['PE__LOG'],
}

_enum_PacketFilter = {
    'Cannot_BPF_Shunt_Conn': Notice_Type['PacketFilter__Cannot_BPF_Shunt_Conn'],
    'Compile_Failure': Notice_Type['PacketFilter__Compile_Failure'],
    'DefaultPcapFilter': zeek_PcapFilterID['PacketFilter__DefaultPcapFilter'],
    'Dropped_Packets': Notice_Type['PacketFilter__Dropped_Packets'],
    'FilterTester': zeek_PcapFilterID['PacketFilter__FilterTester'],
    'Install_Failure': Notice_Type['PacketFilter__Install_Failure'],
    'LOG': Log_ID['PacketFilter__LOG'],
    'No_More_Conn_Shunts_Available': Notice_Type['PacketFilter__No_More_Conn_Shunts_Available'],
    'Too_Long_To_Compile_Filter': Notice_Type['PacketFilter__Too_Long_To_Compile_Filter'],
}

_enum_ProtocolDetector = {
    'BOTH': ProtocolDetector_dir['BOTH'],
    'INCOMING': ProtocolDetector_dir['INCOMING'],
    'NONE': ProtocolDetector_dir['NONE'],
    'OUTGOING': ProtocolDetector_dir['OUTGOING'],
    'Protocol_Found': Notice_Type['ProtocolDetector__Protocol_Found'],
    'Server_Found': Notice_Type['ProtocolDetector__Server_Found'],
    'dir': ProtocolDetector_dir,
}

_enum_RADIUS = {
    'LOG': Log_ID['RADIUS__LOG'],
}

_enum_RDP = {
    'LOG': Log_ID['RDP__LOG'],
}

_enum_RFB = {
    'LOG': Log_ID['RFB__LOG'],
}

_enum_Reporter = {
    'ERROR': Reporter_Level['ERROR'],
    'INFO': Reporter_Level['INFO'],
    'LOG': Log_ID['Reporter__LOG'],
    'Level': Reporter_Level,
    'WARNING': Reporter_Level['WARNING'],
}

_enum_SIP = {
    'LOG': Log_ID['SIP__LOG'],
}

_enum_SMB = {
    'AUTH_LOG': Log_ID['SMB__AUTH_LOG'],
    'Action': SMB_Action,
    'CMD_LOG': Log_ID['SMB__CMD_LOG'],
    'FILES_LOG': Log_ID['SMB__FILES_LOG'],
    'FILE_CLOSE': SMB_Action['FILE_CLOSE'],
    'FILE_DELETE': SMB_Action['FILE_DELETE'],
    'FILE_OPEN': SMB_Action['FILE_OPEN'],
    'FILE_READ': SMB_Action['FILE_READ'],
    'FILE_RENAME': SMB_Action['FILE_RENAME'],
    'FILE_SET_ATTRIBUTE': SMB_Action['FILE_SET_ATTRIBUTE'],
    'FILE_WRITE': SMB_Action['FILE_WRITE'],
    'IN_FILE_NAME': Intel_Where['SMB__IN_FILE_NAME'],
    'MAPPING_LOG': Log_ID['SMB__MAPPING_LOG'],
    'PIPE_CLOSE': SMB_Action['PIPE_CLOSE'],
    'PIPE_OPEN': SMB_Action['PIPE_OPEN'],
    'PIPE_READ': SMB_Action['PIPE_READ'],
    'PIPE_WRITE': SMB_Action['PIPE_WRITE'],
    'PRINT_CLOSE': SMB_Action['PRINT_CLOSE'],
    'PRINT_OPEN': SMB_Action['PRINT_OPEN'],
    'PRINT_READ': SMB_Action['PRINT_READ'],
    'PRINT_WRITE': SMB_Action['PRINT_WRITE'],
}

_enum_SMTP = {
    'Blocklist_Blocked_Host': Notice_Type['SMTP__Blocklist_Blocked_Host'],
    'Blocklist_Error_Message': Notice_Type['SMTP__Blocklist_Error_Message'],
    'IN_CC': Intel_Where['SMTP__IN_CC'],
    'IN_FROM': Intel_Where['SMTP__IN_FROM'],
    'IN_HEADER': Intel_Where['SMTP__IN_HEADER'],
    'IN_MAIL_FROM': Intel_Where['SMTP__IN_MAIL_FROM'],
    'IN_MESSAGE': Intel_Where['SMTP__IN_MESSAGE'],
    'IN_RCPT_TO': Intel_Where['SMTP__IN_RCPT_TO'],
    'IN_RECEIVED_HEADER': Intel_Where['SMTP__IN_RECEIVED_HEADER'],
    'IN_REPLY_TO': Intel_Where['SMTP__IN_REPLY_TO'],
    'IN_TO': Intel_Where['SMTP__IN_TO'],
    'IN_X_ORIGINATING_IP_HEADER': Intel_Where['SMTP__IN_X_ORIGINATING_IP_HEADER'],
    'LOG': Log_ID['SMTP__LOG'],
    'MAIL_CLIENT': Software_Type['SMTP__MAIL_CLIENT'],
    'MAIL_SERVER': Software_Type['SMTP__MAIL_SERVER'],
    'Suspicious_Origination': Notice_Type['SMTP__Suspicious_Origination'],
    'WEBMAIL_SERVER': Software_Type['SMTP__WEBMAIL_SERVER'],
}

_enum_SNMP = {
    'LOG': Log_ID['SNMP__LOG'],
}

_enum_SOCKS = {
    'CONNECTION': SOCKS_RequestType['CONNECTION'],
    'LOG': Log_ID['SOCKS__LOG'],
    'PORT': SOCKS_RequestType['PORT'],
    'RequestType': SOCKS_RequestType,
    'UDP_ASSOCIATE': SOCKS_RequestType['UDP_ASSOCIATE'],
}

_enum_SSH = {
    'CLIENT': Software_Type['SSH__CLIENT'],
    'IN_SERVER_HOST_KEY': Intel_Where['SSH__IN_SERVER_HOST_KEY'],
    'Interesting_Hostname_Login': Notice_Type['SSH__Interesting_Hostname_Login'],
    'LOG': Log_ID['SSH__LOG'],
    'Login_By_Password_Guesser': Notice_Type['SSH__Login_By_Password_Guesser'],
    'Password_Guessing': Notice_Type['SSH__Password_Guessing'],
    'SERVER': Software_Type['SSH__SERVER'],
    'SUCCESSFUL_LOGIN': Intel_Where['SSH__SUCCESSFUL_LOGIN'],
    'Watched_Country_Login': Notice_Type['SSH__Watched_Country_Login'],
}

_enum_SSL = {
    'Certificate_Expired': Notice_Type['SSL__Certificate_Expired'],
    'Certificate_Expires_Soon': Notice_Type['SSL__Certificate_Expires_Soon'],
    'Certificate_Not_Valid_Yet': Notice_Type['SSL__Certificate_Not_Valid_Yet'],
    'IN_SERVER_NAME': Intel_Where['SSL__IN_SERVER_NAME'],
    'Invalid_Ocsp_Response': Notice_Type['SSL__Invalid_Ocsp_Response'],
    'Invalid_Server_Cert': Notice_Type['SSL__Invalid_Server_Cert'],
    'LOG': Log_ID['SSL__LOG'],
    'Old_Version': Notice_Type['SSL__Old_Version'],
    'SCT_OCSP_EXT': SSL_SctSource['SCT_OCSP_EXT'],
    'SCT_TLS_EXT': SSL_SctSource['SCT_TLS_EXT'],
    'SCT_X509_EXT': SSL_SctSource['SCT_X509_EXT'],
    'SctSource': SSL_SctSource,
    'Weak_Cipher': Notice_Type['SSL__Weak_Cipher'],
    'Weak_Key': Notice_Type['SSL__Weak_Key'],
}

_enum_Scan = {
    'Address_Scan': Notice_Type['Scan__Address_Scan'],
    'Port_Scan': Notice_Type['Scan__Port_Scan'],
}

_enum_Signatures = {
    'Action': Signatures_Action,
    'Count_Signature': Notice_Type['Signatures__Count_Signature'],
    'LOG': Log_ID['Signatures__LOG'],
    'Multiple_Sig_Responders': Notice_Type['Signatures__Multiple_Sig_Responders'],
    'Multiple_Signatures': Notice_Type['Signatures__Multiple_Signatures'],
    'SIG_ALARM': Signatures_Action['SIG_ALARM'],
    'SIG_ALARM_ONCE': Signatures_Action['SIG_ALARM_ONCE'],
    'SIG_ALARM_PER_ORIG': Signatures_Action['SIG_ALARM_PER_ORIG'],
    'SIG_COUNT_PER_RESP': Signatures_Action['SIG_COUNT_PER_RESP'],
    'SIG_FILE_BUT_NO_SCAN': Signatures_Action['SIG_FILE_BUT_NO_SCAN'],
    'SIG_IGNORE': Signatures_Action['SIG_IGNORE'],
    'SIG_LOG': Signatures_Action['SIG_LOG'],
    'SIG_QUIET': Signatures_Action['SIG_QUIET'],
    'SIG_SUMMARY': Signatures_Action['SIG_SUMMARY'],
    'Sensitive_Signature': Notice_Type['Signatures__Sensitive_Signature'],
    'Signature_Summary': Notice_Type['Signatures__Signature_Summary'],
}

_enum_Software = {
    'LOG': Log_ID['Software__LOG'],
    'Software_Version_Change': Notice_Type['Software__Software_Version_Change'],
    'Type': Software_Type,
    'UNKNOWN': Software_Type['UNKNOWN'],
    'Vulnerable_Version': Notice_Type['Software__Vulnerable_Version'],
}

_enum_Stats = {
    'LOG': Log_ID['Stats__LOG'],
}

_enum_SumStats = {
    'AVERAGE': SumStats_Calculation['AVERAGE'],
    'Calculation': SumStats_Calculation,
    'HLL_UNIQUE': SumStats_Calculation['HLL_UNIQUE'],
    'LAST': SumStats_Calculation['LAST'],
    'MAX': SumStats_Calculation['MAX'],
    'MIN': SumStats_Calculation['MIN'],
    'PLACEHOLDER': SumStats_Calculation['PLACEHOLDER'],
    'SAMPLE': SumStats_Calculation['SAMPLE'],
    'STD_DEV': SumStats_Calculation['STD_DEV'],
    'SUM': SumStats_Calculation['SUM'],
    'TOPK': SumStats_Calculation['TOPK'],
    'UNIQUE': SumStats_Calculation['UNIQUE'],
    'VARIANCE': SumStats_Calculation['VARIANCE'],
}

_enum_Supervisor = {
    'ClusterRole': Supervisor_ClusterRole,
    'LOGGER': Supervisor_ClusterRole['LOGGER'],
    'MANAGER': Supervisor_ClusterRole['MANAGER'],
    'NONE': Supervisor_ClusterRole['NONE'],
    'PROXY': Supervisor_ClusterRole['PROXY'],
    'WORKER': Supervisor_ClusterRole['WORKER'],
}

_enum_Syslog = {
    'LOG': Log_ID['Syslog__LOG'],
}

_enum_TeamCymruMalwareHashRegistry = {
    'Match': Notice_Type['TeamCymruMalwareHashRegistry__Match'],
}

_enum_Traceroute = {
    'Detected': Notice_Type['Traceroute__Detected'],
    'LOG': Log_ID['Traceroute__LOG'],
}

_enum_Tunnel = {
    'AYIYA': Tunnel_Type['AYIYA'],
    'Action': Tunnel_Action,
    'CLOSE': Tunnel_Action['CLOSE'],
    'DISCOVER': Tunnel_Action['DISCOVER'],
    'EXPIRE': Tunnel_Action['EXPIRE'],
    'GRE': Tunnel_Type['GRE'],
    'GTPv1': Tunnel_Type['GTPv1'],
    'HTTP': Tunnel_Type['HTTP'],
    'IP': Tunnel_Type['IP'],
    'LOG': Log_ID['Tunnel__LOG'],
    'NONE': Tunnel_Type['NONE'],
    'SOCKS': Tunnel_Type['SOCKS'],
    'TEREDO': Tunnel_Type['TEREDO'],
    'Type': Tunnel_Type,
    'VXLAN': Tunnel_Type['VXLAN'],
}

_enum_Unified2 = {
    'LOG': Log_ID['Unified2__LOG'],
}

_enum_Weird = {
    'ACTION_IGNORE': Weird_Action['ACTION_IGNORE'],
    'ACTION_LOG': Weird_Action['ACTION_LOG'],
    'ACTION_LOG_ONCE': Weird_Action['ACTION_LOG_ONCE'],
    'ACTION_LOG_PER_CONN': Weird_Action['ACTION_LOG_PER_CONN'],
    'ACTION_LOG_PER_ORIG': Weird_Action['ACTION_LOG_PER_ORIG'],
    'ACTION_NOTICE': Weird_Action['ACTION_NOTICE'],
    'ACTION_NOTICE_ONCE': Weird_Action['ACTION_NOTICE_ONCE'],
    'ACTION_NOTICE_PER_CONN': Weird_Action['ACTION_NOTICE_PER_CONN'],
    'ACTION_NOTICE_PER_ORIG': Weird_Action['ACTION_NOTICE_PER_ORIG'],
    'ACTION_UNSPECIFIED': Weird_Action['ACTION_UNSPECIFIED'],
    'Action': Weird_Action,
    'Activity': Notice_Type['Weird__Activity'],
    'LOG': Log_ID['Weird__LOG'],
}

_enum_WeirdStats = {
    'LOG': Log_ID['WeirdStats__LOG'],
}

_enum_X509 = {
    'IN_CERT': Intel_Where['X509__IN_CERT'],
    'LOG': Log_ID['X509__LOG'],
}

_enum_ZeekygenExample = {
    'FIVE': ZeekygenExample_SimpleEnum['FIVE'],
    'FOUR': ZeekygenExample_SimpleEnum['FOUR'],
    'LOG': Log_ID['ZeekygenExample__LOG'],
    'ONE': ZeekygenExample_SimpleEnum['ONE'],
    'SimpleEnum': ZeekygenExample_SimpleEnum,
    'THREE': ZeekygenExample_SimpleEnum['THREE'],
    'TWO': ZeekygenExample_SimpleEnum['TWO'],
    'Zeekygen_Four': Notice_Type['ZeekygenExample__Zeekygen_Four'],
    'Zeekygen_One': Notice_Type['ZeekygenExample__Zeekygen_One'],
    'Zeekygen_Three': Notice_Type['ZeekygenExample__Zeekygen_Three'],
    'Zeekygen_Two': Notice_Type['ZeekygenExample__Zeekygen_Two'],
}

_enum_mysql = {
    'LOG': Log_ID['mysql__LOG'],
}

_enum_zeek = {
    'ALL_HOSTS': zeek_Host['ALL_HOSTS'],
    'BIDIRECTIONAL': zeek_Direction['BIDIRECTIONAL'],
    'Direction': zeek_Direction,
    'Host': zeek_Host,
    'INBOUND': zeek_Direction['INBOUND'],
    'IPAddrAnonymization': zeek_IPAddrAnonymization,
    'IPAddrAnonymizationClass': zeek_IPAddrAnonymizationClass,
    'KEEP_ORIG_ADDR': zeek_IPAddrAnonymization['KEEP_ORIG_ADDR'],
    'L3_ARP': zeek_layer3_proto['L3_ARP'],
    'L3_IPV4': zeek_layer3_proto['L3_IPV4'],
    'L3_IPV6': zeek_layer3_proto['L3_IPV6'],
    'L3_UNKNOWN': zeek_layer3_proto['L3_UNKNOWN'],
    'LINK_ETHERNET': zeek_link_encap['LINK_ETHERNET'],
    'LINK_UNKNOWN': zeek_link_encap['LINK_UNKNOWN'],
    'LOCAL_HOSTS': zeek_Host['LOCAL_HOSTS'],
    'NO_DIRECTION': zeek_Direction['NO_DIRECTION'],
    'NO_HOSTS': zeek_Host['NO_HOSTS'],
    'None': zeek_PcapFilterID['None'],
    'ORIG_ADDR': zeek_IPAddrAnonymizationClass['ORIG_ADDR'],
    'OTHER_ADDR': zeek_IPAddrAnonymizationClass['OTHER_ADDR'],
    'OUTBOUND': zeek_Direction['OUTBOUND'],
    'PKT_PROFILE_MODE_BYTES': zeek_pkt_profile_modes['PKT_PROFILE_MODE_BYTES'],
    'PKT_PROFILE_MODE_NONE': zeek_pkt_profile_modes['PKT_PROFILE_MODE_NONE'],
    'PKT_PROFILE_MODE_PKTS': zeek_pkt_profile_modes['PKT_PROFILE_MODE_PKTS'],
    'PKT_PROFILE_MODE_SECS': zeek_pkt_profile_modes['PKT_PROFILE_MODE_SECS'],
    'PREFIX_PRESERVING_A50': zeek_IPAddrAnonymization['PREFIX_PRESERVING_A50'],
    'PREFIX_PRESERVING_MD5': zeek_IPAddrAnonymization['PREFIX_PRESERVING_MD5'],
    'PcapFilterID': zeek_PcapFilterID,
    'RANDOM_MD5': zeek_IPAddrAnonymization['RANDOM_MD5'],
    'REMOTE_HOSTS': zeek_Host['REMOTE_HOSTS'],
    'RESP_ADDR': zeek_IPAddrAnonymizationClass['RESP_ADDR'],
    'RPC_AUTH_ERROR': zeek_rpc_status['RPC_AUTH_ERROR'],
    'RPC_GARBAGE_ARGS': zeek_rpc_status['RPC_GARBAGE_ARGS'],
    'RPC_PROC_UNAVAIL': zeek_rpc_status['RPC_PROC_UNAVAIL'],
    'RPC_PROG_MISMATCH': zeek_rpc_status['RPC_PROG_MISMATCH'],
    'RPC_PROG_UNAVAIL': zeek_rpc_status['RPC_PROG_UNAVAIL'],
    'RPC_SUCCESS': zeek_rpc_status['RPC_SUCCESS'],
    'RPC_SYSTEM_ERR': zeek_rpc_status['RPC_SYSTEM_ERR'],
    'RPC_TIMEOUT': zeek_rpc_status['RPC_TIMEOUT'],
    'RPC_UNKNOWN_ERROR': zeek_rpc_status['RPC_UNKNOWN_ERROR'],
    'RPC_VERS_MISMATCH': zeek_rpc_status['RPC_VERS_MISMATCH'],
    'SEQUENTIALLY_NUMBERED': zeek_IPAddrAnonymization['SEQUENTIALLY_NUMBERED'],
    'TABLE_ELEMENT_CHANGED': zeek_TableChange['TABLE_ELEMENT_CHANGED'],
    'TABLE_ELEMENT_EXPIRED': zeek_TableChange['TABLE_ELEMENT_EXPIRED'],
    'TABLE_ELEMENT_NEW': zeek_TableChange['TABLE_ELEMENT_NEW'],
    'TABLE_ELEMENT_REMOVED': zeek_TableChange['TABLE_ELEMENT_REMOVED'],
    'TableChange': zeek_TableChange,
    'icmp': zeek_transport_proto['icmp'],
    'layer3_proto': zeek_layer3_proto,
    'link_encap': zeek_link_encap,
    'pkt_profile_modes': zeek_pkt_profile_modes,
    'rpc_status': zeek_rpc_status,
    'tcp': zeek_transport_proto['tcp'],
    'transport_proto': zeek_transport_proto,
    'udp': zeek_transport_proto['udp'],
    'unknown_transport': zeek_transport_proto['unknown_transport'],
}


def globals(*namespaces, bare: bool = False) -> 'Dict[str, Enum]':  # pylint: disable=redefined-builtin
    """Generate Bro/Zeek ``enum`` namespace.

    Args:
        *namespaces: Namespaces to be loaded.
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Keyword Args:
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Returns:
        :obj:`dict` mapping of :obj:`str` and :obj:`Enum`: Global enum namespace.

    Warns:
        BroDeprecationWarning: If ``bro`` namespace used.

    Raises:
        :exc:`ValueError`: If ``namespace`` is not defined.

    Note:
        For back-port compatibility, the ``bro`` namespace is an alias of the
        ``zeek`` namespace.

    """
    if bare:
        enum_data = dict()
    else:
        enum_data = _enum_zeek.copy()
    for namespace in namespaces:
        if namespace == 'bro':
            warnings.warn("Use of 'bro' is deprecated. "
                          "Please use 'zeek' instead.", BroDeprecationWarning)
            namespace = 'zeek'

        enum_dict = globals().get('_enum_%s' % namespace)
        if enum_dict is None:
            raise ValueError('undefined namespace: %s' % namespace)
        enum_data.update(enum_dict)
    return enum_data
