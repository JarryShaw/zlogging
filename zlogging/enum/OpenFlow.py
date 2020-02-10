# -*- coding: utf-8 -*-
"""Namespace: ``OpenFlow``."""

from zlogging._compat import enum


@enum.unique
class ofp_action_type(enum.IntFlag):
    """Openflow action\_type definitions.

    The openflow action type defines
    what actions openflow can take
    to modify a packet

    c.f. `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html#type-OpenFlow::ofp_action_type>`__

    """

    _ignore_ = 'ofp_action_type _'
    ofp_action_type = vars()

    #: Output to switch port.
    ofp_action_type['OFPAT_OUTPUT'] = enum.auto()

    #: Set the 802.1q VLAN id.
    ofp_action_type['OFPAT_SET_VLAN_VID'] = enum.auto()

    #: Set the 802.1q priority.
    ofp_action_type['OFPAT_SET_VLAN_PCP'] = enum.auto()

    #: Strip the 802.1q header.
    ofp_action_type['OFPAT_STRIP_VLAN'] = enum.auto()

    #: Ethernet source address.
    ofp_action_type['OFPAT_SET_DL_SRC'] = enum.auto()

    #: Ethernet destination address.
    ofp_action_type['OFPAT_SET_DL_DST'] = enum.auto()

    #: IP source address.
    ofp_action_type['OFPAT_SET_NW_SRC'] = enum.auto()

    #: IP destination address.
    ofp_action_type['OFPAT_SET_NW_DST'] = enum.auto()

    #: IP ToS (DSCP field, 6 bits).
    ofp_action_type['OFPAT_SET_NW_TOS'] = enum.auto()

    #: TCP/UDP source port.
    ofp_action_type['OFPAT_SET_TP_SRC'] = enum.auto()

    #: TCP/UDP destination port.
    ofp_action_type['OFPAT_SET_TP_DST'] = enum.auto()

    #: Output to queue.
    ofp_action_type['OFPAT_ENQUEUE'] = enum.auto()

    #: Vendor specific.
    ofp_action_type['OFPAT_VENDOR'] = enum.auto()


@enum.unique
class ofp_config_flags(enum.IntFlag):
    """Openflow config flag definitions.

    TODO: describe

    c.f. `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html#type-OpenFlow::ofp_config_flags>`__

    """

    _ignore_ = 'ofp_config_flags _'
    ofp_config_flags = vars()

    #: No special handling for fragments.
    ofp_config_flags['OFPC_FRAG_NORMAL'] = enum.auto()

    #: Drop fragments.
    ofp_config_flags['OFPC_FRAG_DROP'] = enum.auto()

    #: Reassemble (only if OFPC\_IP\_REASM set).
    ofp_config_flags['OFPC_FRAG_REASM'] = enum.auto()

    ofp_config_flags['OFPC_FRAG_MASK'] = enum.auto()


@enum.unique
class ofp_flow_mod_command(enum.IntFlag):
    """Openflow flow\_mod\_command definitions.

    The openflow flow\_mod\_command describes
    of what kind an action is.

    c.f. `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html#type-OpenFlow::ofp_flow_mod_command>`__

    """

    _ignore_ = 'ofp_flow_mod_command _'
    ofp_flow_mod_command = vars()

    #: New flow.
    ofp_flow_mod_command['OFPFC_ADD'] = enum.auto()

    #: Modify all matching flows.
    ofp_flow_mod_command['OFPFC_MODIFY'] = enum.auto()

    #: Modify entry strictly matching wildcards.
    ofp_flow_mod_command['OFPFC_MODIFY_STRICT'] = enum.auto()

    #: Delete all matching flows.
    ofp_flow_mod_command['OFPFC_DELETE'] = enum.auto()

    #: Strictly matching wildcards and priority.
    ofp_flow_mod_command['OFPFC_DELETE_STRICT'] = enum.auto()


@enum.unique
class Plugin(enum.IntFlag):
    """Available openflow plugins.

    c.f. `base/frameworks/openflow/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/types.zeek.html#type-OpenFlow::Plugin>`__

    """

    _ignore_ = 'Plugin _'
    Plugin = vars()

    #: Internal placeholder plugin.
    Plugin['INVALID'] = enum.auto()

    #: (present if base/frameworks/openflow/plugins/ryu.zeek is loaded)
    Plugin['RYU'] = enum.auto()

    #: (present if base/frameworks/openflow/plugins/log.zeek is loaded)
    Plugin['OFLOG'] = enum.auto()

    #: (present if base/frameworks/openflow/plugins/broker.zeek is loaded)
    Plugin['BROKER'] = enum.auto()
