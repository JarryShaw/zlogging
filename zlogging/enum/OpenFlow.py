# -*- coding: utf-8 -*-
"""Namespace: OpenFlow.

:module: zlogging.enum.OpenFlow
"""

from zlogging._compat import enum


@enum.unique
class ofp_action_type(enum.IntFlag):
    """Openflow action_type definitions.

    The openflow action type defines
    what actions openflow can take
    to modify a packet

    c.f. `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html>`__

    """

    _ignore_ = 'ofp_action_type _'
    ofp_action_type = vars()

    #: Output to switch port.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_OUTPUT'] = enum.auto()

    #: Set the 802.1q VLAN id.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_VLAN_VID'] = enum.auto()

    #: Set the 802.1q priority.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_VLAN_PCP'] = enum.auto()

    #: Strip the 802.1q header.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_STRIP_VLAN'] = enum.auto()

    #: Ethernet source address.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_DL_SRC'] = enum.auto()

    #: Ethernet destination address.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_DL_DST'] = enum.auto()

    #: IP source address.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_NW_SRC'] = enum.auto()

    #: IP destination address.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_NW_DST'] = enum.auto()

    #: IP ToS (DSCP field, 6 bits).
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_NW_TOS'] = enum.auto()

    #: TCP/UDP source port.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_TP_SRC'] = enum.auto()

    #: TCP/UDP destination port.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_SET_TP_DST'] = enum.auto()

    #: Output to queue.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_ENQUEUE'] = enum.auto()

    #: Vendor specific.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_action_type['OFPAT_VENDOR'] = enum.auto()


@enum.unique
class ofp_config_flags(enum.IntFlag):
    """Openflow config flag definitions.

    TODO: describe

    c.f. `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html>`__

    """

    _ignore_ = 'ofp_config_flags _'
    ofp_config_flags = vars()

    #: No special handling for fragments.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_config_flags['OFPC_FRAG_NORMAL'] = enum.auto()

    #: Drop fragments.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_config_flags['OFPC_FRAG_DROP'] = enum.auto()

    #: Reassemble (only if OFPC_IP_REASM set).
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_config_flags['OFPC_FRAG_REASM'] = enum.auto()

    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_config_flags['OFPC_FRAG_MASK'] = enum.auto()


@enum.unique
class ofp_flow_mod_command(enum.IntFlag):
    """Openflow flow_mod_command definitions.

    The openflow flow_mod_command describes
    of what kind an action is.

    c.f. `base/frameworks/openflow/consts.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/consts.zeek.html>`__

    """

    _ignore_ = 'ofp_flow_mod_command _'
    ofp_flow_mod_command = vars()

    #: New flow.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_flow_mod_command['OFPFC_ADD'] = enum.auto()

    #: Modify all matching flows.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_flow_mod_command['OFPFC_MODIFY'] = enum.auto()

    #: Modify entry strictly matching wildcards.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_flow_mod_command['OFPFC_MODIFY_STRICT'] = enum.auto()

    #: Delete all matching flows.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_flow_mod_command['OFPFC_DELETE'] = enum.auto()

    #: Strictly matching wildcards and priority.
    #: :currentmodule: zlogging.enum.OpenFlow
    ofp_flow_mod_command['OFPFC_DELETE_STRICT'] = enum.auto()


@enum.unique
class Plugin(enum.IntFlag):
    """Available openflow plugins.

    c.f. `base/frameworks/openflow/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/openflow/types.zeek.html>`__

    """

    _ignore_ = 'Plugin _'
    Plugin = vars()

    #: Internal placeholder plugin.
    #: :currentmodule: zlogging.enum.OpenFlow
    Plugin['INVALID'] = enum.auto()

    #: (present if base/frameworks/openflow/plugins/ryu.zeek is loaded)
    #: :currentmodule: zlogging.enum.OpenFlow
    Plugin['RYU'] = enum.auto()

    #: (present if base/frameworks/openflow/plugins/log.zeek is loaded)
    #: :currentmodule: zlogging.enum.OpenFlow
    Plugin['OFLOG'] = enum.auto()

    #: (present if base/frameworks/openflow/plugins/broker.zeek is loaded)
    #: :currentmodule: zlogging.enum.OpenFlow
    Plugin['BROKER'] = enum.auto()
