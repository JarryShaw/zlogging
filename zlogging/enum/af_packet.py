# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``AF_Packet``."""

from zlogging._compat import enum


@enum.unique
class ChecksumMode(enum.IntFlag):
    """Enum: ``AF_Packet::ChecksumMode``.

    Available checksum validation modes.

    See Also:
        `base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek.html#type-AF_Packet::ChecksumMode>`__

    """

    _ignore_ = 'ChecksumMode _'
    ChecksumMode = vars()

    #: Ignore checksums, i.e. always assume they are correct.
    CHECKSUM_OFF = enum.auto()

    #: Let Zeek compute and verify checksums.
    CHECKSUM_ON = enum.auto()

    #: Let the kernel handle checksum offloading.
    #: Note: Semantics may depend on the kernel and driver version.
    CHECKSUM_KERNEL = enum.auto()


@enum.unique
class FanoutMode(enum.IntFlag):
    """Enum: ``AF_Packet::FanoutMode``.

    Available fanout modes.

    See Also:
        `base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek <https://docs.zeek.org/en/stable/scripts/base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek.html#type-AF_Packet::FanoutMode>`__

    """

    _ignore_ = 'FanoutMode _'
    FanoutMode = vars()

    FANOUT_HASH = enum.auto()

    FANOUT_CPU = enum.auto()

    FANOUT_QM = enum.auto()

    FANOUT_CBPF = enum.auto()

    FANOUT_EBPF = enum.auto()
