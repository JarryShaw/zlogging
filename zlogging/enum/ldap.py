# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``LDAP``."""

from zlogging._compat import enum


@enum.unique
class ProtocolOpcode(enum.IntFlag):
    """Enum: ``LDAP::ProtocolOpcode``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-LDAP::ProtocolOpcode>`__

    """

    _ignore_ = 'ProtocolOpcode _'
    ProtocolOpcode = vars()

    ProtocolOpcode_BIND_REQUEST = enum.auto()

    ProtocolOpcode_BIND_RESPONSE = enum.auto()

    ProtocolOpcode_UNBIND_REQUEST = enum.auto()

    ProtocolOpcode_SEARCH_REQUEST = enum.auto()

    ProtocolOpcode_SEARCH_RESULT_ENTRY = enum.auto()

    ProtocolOpcode_SEARCH_RESULT_DONE = enum.auto()

    ProtocolOpcode_MODIFY_REQUEST = enum.auto()

    ProtocolOpcode_MODIFY_RESPONSE = enum.auto()

    ProtocolOpcode_ADD_REQUEST = enum.auto()

    ProtocolOpcode_ADD_RESPONSE = enum.auto()

    ProtocolOpcode_DEL_REQUEST = enum.auto()

    ProtocolOpcode_DEL_RESPONSE = enum.auto()

    ProtocolOpcode_MOD_DN_REQUEST = enum.auto()

    ProtocolOpcode_MOD_DN_RESPONSE = enum.auto()

    ProtocolOpcode_COMPARE_REQUEST = enum.auto()

    ProtocolOpcode_COMPARE_RESPONSE = enum.auto()

    ProtocolOpcode_ABANDON_REQUEST = enum.auto()

    ProtocolOpcode_SEARCH_RESULT_REFERENCE = enum.auto()

    ProtocolOpcode_EXTENDED_REQUEST = enum.auto()

    ProtocolOpcode_EXTENDED_RESPONSE = enum.auto()

    ProtocolOpcode_INTERMEDIATE_RESPONSE = enum.auto()

    ProtocolOpcode_Undef = enum.auto()


@enum.unique
class ResultCode(enum.IntFlag):
    """Enum: ``LDAP::ResultCode``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-LDAP::ResultCode>`__

    """

    _ignore_ = 'ResultCode _'
    ResultCode = vars()

    ResultCode_SUCCESS = enum.auto()

    ResultCode_OPERATIONS_ERROR = enum.auto()

    ResultCode_PROTOCOL_ERROR = enum.auto()

    ResultCode_TIME_LIMIT_EXCEEDED = enum.auto()

    ResultCode_SIZE_LIMIT_EXCEEDED = enum.auto()

    ResultCode_COMPARE_FALSE = enum.auto()

    ResultCode_COMPARE_TRUE = enum.auto()

    ResultCode_AUTH_METHOD_NOT_SUPPORTED = enum.auto()

    ResultCode_STRONGER_AUTH_REQUIRED = enum.auto()

    ResultCode_PARTIAL_RESULTS = enum.auto()

    ResultCode_REFERRAL = enum.auto()

    ResultCode_ADMIN_LIMIT_EXCEEDED = enum.auto()

    ResultCode_UNAVAILABLE_CRITICAL_EXTENSION = enum.auto()

    ResultCode_CONFIDENTIALITY_REQUIRED = enum.auto()

    ResultCode_SASL_BIND_IN_PROGRESS = enum.auto()

    ResultCode_NO_SUCH_ATTRIBUTE = enum.auto()

    ResultCode_UNDEFINED_ATTRIBUTE_TYPE = enum.auto()

    ResultCode_INAPPROPRIATE_MATCHING = enum.auto()

    ResultCode_CONSTRAINT_VIOLATION = enum.auto()

    ResultCode_ATTRIBUTE_OR_VALUE_EXISTS = enum.auto()

    ResultCode_INVALID_ATTRIBUTE_SYNTAX = enum.auto()

    ResultCode_NO_SUCH_OBJECT = enum.auto()

    ResultCode_ALIAS_PROBLEM = enum.auto()

    ResultCode_INVALID_DNSYNTAX = enum.auto()

    ResultCode_ALIAS_DEREFERENCING_PROBLEM = enum.auto()

    ResultCode_INAPPROPRIATE_AUTHENTICATION = enum.auto()

    ResultCode_INVALID_CREDENTIALS = enum.auto()

    ResultCode_INSUFFICIENT_ACCESS_RIGHTS = enum.auto()

    ResultCode_BUSY = enum.auto()

    ResultCode_UNAVAILABLE = enum.auto()

    ResultCode_UNWILLING_TO_PERFORM = enum.auto()

    ResultCode_LOOP_DETECT = enum.auto()

    ResultCode_SORT_CONTROL_MISSING = enum.auto()

    ResultCode_OFFSET_RANGE_ERROR = enum.auto()

    ResultCode_NAMING_VIOLATION = enum.auto()

    ResultCode_OBJECT_CLASS_VIOLATION = enum.auto()

    ResultCode_NOT_ALLOWED_ON_NON_LEAF = enum.auto()

    ResultCode_NOT_ALLOWED_ON_RDN = enum.auto()

    ResultCode_ENTRY_ALREADY_EXISTS = enum.auto()

    ResultCode_OBJECT_CLASS_MODS_PROHIBITED = enum.auto()

    ResultCode_RESULTS_TOO_LARGE = enum.auto()

    ResultCode_AFFECTS_MULTIPLE_DSAS = enum.auto()

    ResultCode_CONTROL_ERROR = enum.auto()

    ResultCode_OTHER = enum.auto()

    ResultCode_SERVER_DOWN = enum.auto()

    ResultCode_LOCAL_ERROR = enum.auto()

    ResultCode_ENCODING_ERROR = enum.auto()

    ResultCode_DECODING_ERROR = enum.auto()

    ResultCode_TIMEOUT = enum.auto()

    ResultCode_AUTH_UNKNOWN = enum.auto()

    ResultCode_FILTER_ERROR = enum.auto()

    ResultCode_USER_CANCELED = enum.auto()

    ResultCode_PARAM_ERROR = enum.auto()

    ResultCode_NO_MEMORY = enum.auto()

    ResultCode_CONNECT_ERROR = enum.auto()

    ResultCode_NOT_SUPPORTED = enum.auto()

    ResultCode_CONTROL_NOT_FOUND = enum.auto()

    ResultCode_NO_RESULTS_RETURNED = enum.auto()

    ResultCode_MORE_RESULTS_TO_RETURN = enum.auto()

    ResultCode_CLIENT_LOOP = enum.auto()

    ResultCode_REFERRAL_LIMIT_EXCEEDED = enum.auto()

    ResultCode_INVALID_RESPONSE = enum.auto()

    ResultCode_AMBIGUOUS_RESPONSE = enum.auto()

    ResultCode_TLS_NOT_SUPPORTED = enum.auto()

    ResultCode_INTERMEDIATE_RESPONSE = enum.auto()

    ResultCode_UNKNOWN_TYPE = enum.auto()

    ResultCode_LCUP_INVALID_DATA = enum.auto()

    ResultCode_LCUP_UNSUPPORTED_SCHEME = enum.auto()

    ResultCode_LCUP_RELOAD_REQUIRED = enum.auto()

    ResultCode_CANCELED = enum.auto()

    ResultCode_NO_SUCH_OPERATION = enum.auto()

    ResultCode_TOO_LATE = enum.auto()

    ResultCode_CANNOT_CANCEL = enum.auto()

    ResultCode_ASSERTION_FAILED = enum.auto()

    ResultCode_AUTHORIZATION_DENIED = enum.auto()

    ResultCode_Undef = enum.auto()


@enum.unique
class BindAuthType(enum.IntFlag):
    """Enum: ``LDAP::BindAuthType``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-LDAP::BindAuthType>`__

    """

    _ignore_ = 'BindAuthType _'
    BindAuthType = vars()

    BindAuthType_BIND_AUTH_SIMPLE = enum.auto()

    BindAuthType_BIND_AUTH_SASL = enum.auto()

    BindAuthType_SICILY_PACKAGE_DISCOVERY = enum.auto()

    BindAuthType_SICILY_NEGOTIATE = enum.auto()

    BindAuthType_SICILY_RESPONSE = enum.auto()

    BindAuthType_Undef = enum.auto()


@enum.unique
class SearchScope(enum.IntFlag):
    """Enum: ``LDAP::SearchScope``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-LDAP::SearchScope>`__

    """

    _ignore_ = 'SearchScope _'
    SearchScope = vars()

    SearchScope_SEARCH_BASE = enum.auto()

    SearchScope_SEARCH_SINGLE = enum.auto()

    SearchScope_SEARCH_TREE = enum.auto()

    SearchScope_Undef = enum.auto()


@enum.unique
class SearchDerefAlias(enum.IntFlag):
    """Enum: ``LDAP::SearchDerefAlias``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-LDAP::SearchDerefAlias>`__

    """

    _ignore_ = 'SearchDerefAlias _'
    SearchDerefAlias = vars()

    SearchDerefAlias_DEREF_NEVER = enum.auto()

    SearchDerefAlias_DEREF_IN_SEARCHING = enum.auto()

    SearchDerefAlias_DEREF_FINDING_BASE = enum.auto()

    SearchDerefAlias_DEREF_ALWAYS = enum.auto()

    SearchDerefAlias_Undef = enum.auto()
