# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``OpenFlow``."""

from zlogging._compat import enum


@enum.unique
class ofp_action_type(enum.IntFlag):
    """Enum: ``OpenFlow::ofp_action_type``.

    Openflow action_type definitions.

    The openflow action type defines what actions openflow can take to modify a packet.

    See Also:
        `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html#type-OpenFlow::ofp_action_type>`__

    """

    _ignore_ = 'ofp_action_type _'
    ofp_action_type = vars()

    #: Output to switch port.
    OFPAT_OUTPUT = enum.auto()

    #: Set the 802.1q VLAN id.
    OFPAT_SET_VLAN_VID = enum.auto()

    #: Set the 802.1q priority.
    OFPAT_SET_VLAN_PCP = enum.auto()

    #: Strip the 802.1q header.
    OFPAT_STRIP_VLAN = enum.auto()

    #: Ethernet source address.
    OFPAT_SET_DL_SRC = enum.auto()

    #: Ethernet destination address.
    OFPAT_SET_DL_DST = enum.auto()

    #: IP source address.
    OFPAT_SET_NW_SRC = enum.auto()

    #: IP destination address.
    OFPAT_SET_NW_DST = enum.auto()

    #: IP ToS (DSCP field, 6 bits).
    OFPAT_SET_NW_TOS = enum.auto()

    #: TCP/UDP source port.
    OFPAT_SET_TP_SRC = enum.auto()

    #: TCP/UDP destination port.
    OFPAT_SET_TP_DST = enum.auto()

    #: Output to queue.
    OFPAT_ENQUEUE = enum.auto()

    #: Vendor specific.
    OFPAT_VENDOR = enum.auto()


@enum.unique
class ofp_config_flags(enum.IntFlag):
    """Enum: ``OpenFlow::ofp_config_flags``.

    Openflow config flag definitions.

    TODO: describe.

    See Also:
        `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html#type-OpenFlow::ofp_config_flags>`__

    """

    _ignore_ = 'ofp_config_flags _'
    ofp_config_flags = vars()

    #: No special handling for fragments.
    OFPC_FRAG_NORMAL = enum.auto()

    #: Drop fragments.
    OFPC_FRAG_DROP = enum.auto()

    #: Reassemble (only if OFPC\_IP\_REASM set).
    OFPC_FRAG_REASM = enum.auto()

    OFPC_FRAG_MASK = enum.auto()


@enum.unique
class ofp_flow_mod_command(enum.IntFlag):
    """Enum: ``OpenFlow::ofp_flow_mod_command``.

    Openflow flow_mod_command definitions.

    The openflow flow_mod_command describes of what kind an action is.

    See Also:
        `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html#type-OpenFlow::ofp_flow_mod_command>`__

    """

    _ignore_ = 'ofp_flow_mod_command _'
    ofp_flow_mod_command = vars()

    #: New flow.
    OFPFC_ADD = enum.auto()

    #: Modify all matching flows.
    OFPFC_MODIFY = enum.auto()

    #: Modify entry strictly matching wildcards.
    OFPFC_MODIFY_STRICT = enum.auto()

    #: Delete all matching flows.
    OFPFC_DELETE = enum.auto()

    #: Strictly matching wildcards and priority.
    OFPFC_DELETE_STRICT = enum.auto()


@enum.unique
class Plugin(enum.IntFlag):
    """Enum: ``OpenFlow::Plugin``.

    Available openflow plugins.

    See Also:
        `base/frameworks/openflow/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/types.zeek.html#type-OpenFlow::Plugin>`__

    """

    _ignore_ = 'Plugin _'
    Plugin = vars()

    #: Internal placeholder plugin.
    INVALID = enum.auto()

    #: (present if base/frameworks/openflow/plugins/ryu.zeek is loaded)
    RYU = enum.auto()

    #: (present if base/frameworks/openflow/plugins/log.zeek is loaded)
    OFLOG = enum.auto()

    #: (present if base/frameworks/openflow/plugins/broker.zeek is loaded)
    BROKER = enum.auto()
