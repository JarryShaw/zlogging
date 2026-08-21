# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``ASN1``."""

from zlogging._compat import enum


@enum.unique
class ASN1Type(enum.IntFlag):
    """Enum: ``ASN1::ASN1Type``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-ASN1::ASN1Type>`__

    """

    _ignore_ = 'ASN1Type _'
    ASN1Type = vars()

    ASN1Type_Boolean = enum.auto()

    ASN1Type_Integer = enum.auto()

    ASN1Type_BitString = enum.auto()

    ASN1Type_OctetString = enum.auto()

    ASN1Type_NullVal = enum.auto()

    ASN1Type_ObjectIdentifier = enum.auto()

    ASN1Type_ObjectDescriptor = enum.auto()

    ASN1Type_InstanceOf = enum.auto()

    ASN1Type_Real = enum.auto()

    ASN1Type_Enumerated = enum.auto()

    ASN1Type_EmbeddedPDV = enum.auto()

    ASN1Type_UTF8String = enum.auto()

    ASN1Type_RelativeOID = enum.auto()

    ASN1Type_Sequence = enum.auto()

    ASN1Type_Set = enum.auto()

    ASN1Type_NumericString = enum.auto()

    ASN1Type_PrintableString = enum.auto()

    ASN1Type_TeletextString = enum.auto()

    ASN1Type_VideotextString = enum.auto()

    ASN1Type_IA5String = enum.auto()

    ASN1Type_UTCTime = enum.auto()

    ASN1Type_GeneralizedTime = enum.auto()

    ASN1Type_GraphicString = enum.auto()

    ASN1Type_VisibleString = enum.auto()

    ASN1Type_GeneralString = enum.auto()

    ASN1Type_UniversalString = enum.auto()

    ASN1Type_CharacterString = enum.auto()

    ASN1Type_BMPString = enum.auto()

    ASN1Type_Undef = enum.auto()


@enum.unique
class ASN1Class(enum.IntFlag):
    """Enum: ``ASN1::ASN1Class``.

    See Also:
        `Protocol Analyzers <https://docs.zeek.org/en/stable/scripts/Protocol Analyzers.html#type-ASN1::ASN1Class>`__

    """

    _ignore_ = 'ASN1Class _'
    ASN1Class = vars()

    ASN1Class_Universal = enum.auto()

    ASN1Class_Application = enum.auto()

    ASN1Class_ContextSpecific = enum.auto()

    ASN1Class_Private = enum.auto()

    ASN1Class_Undef = enum.auto()
