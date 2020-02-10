# -*- coding: utf-8 -*-
"""Namespace: NetControl.

:module: zlogging.enum.NetControl
"""

from zlogging._compat import enum


@enum.unique
class InfoCategory(enum.IntFlag):
    """Type of an entry in the NetControl log.

    c.f. `base/frameworks/netcontrol/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/main.zeek.html>`__

    """

    _ignore_ = 'InfoCategory _'
    InfoCategory = vars()

    #: A log entry reflecting a framework message.
    #: :currentmodule: zlogging.enum.NetControl
    InfoCategory['MESSAGE'] = enum.auto()

    #: A log entry reflecting a framework message.
    #: :currentmodule: zlogging.enum.NetControl
    InfoCategory['ERROR'] = enum.auto()

    #: A log entry about a rule.
    #: :currentmodule: zlogging.enum.NetControl
    InfoCategory['RULE'] = enum.auto()


@enum.unique
class InfoState(enum.IntFlag):
    """State of an entry in the NetControl log.

    c.f. `base/frameworks/netcontrol/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/main.zeek.html>`__

    """

    _ignore_ = 'InfoState _'
    InfoState = vars()

    #: The request to add/remove a rule was sent to the respective backend.
    #: :currentmodule: zlogging.enum.NetControl
    InfoState['REQUESTED'] = enum.auto()

    #: A rule was successfully added by a backend.
    #: :currentmodule: zlogging.enum.NetControl
    InfoState['SUCCEEDED'] = enum.auto()

    #: A backend reported that a rule was already existing.
    #: :currentmodule: zlogging.enum.NetControl
    InfoState['EXISTS'] = enum.auto()

    #: A rule addition failed.
    #: :currentmodule: zlogging.enum.NetControl
    InfoState['FAILED'] = enum.auto()

    #: A rule was successfully removed by a backend.
    #: :currentmodule: zlogging.enum.NetControl
    InfoState['REMOVED'] = enum.auto()

    #: A rule timeout was triggered by the NetControl framework or a backend.
    #: :currentmodule: zlogging.enum.NetControl
    InfoState['TIMEOUT'] = enum.auto()


@enum.unique
class EntityType(enum.IntFlag):
    """Type defining the entity that a rule applies to.

    c.f. `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html>`__

    """

    _ignore_ = 'EntityType _'
    EntityType = vars()

    #: Activity involving a specific IP address.
    #: :currentmodule: zlogging.enum.NetControl
    EntityType['ADDRESS'] = enum.auto()

    #: Activity involving all of a bi-directional connection’s activity.
    #: :currentmodule: zlogging.enum.NetControl
    EntityType['CONNECTION'] = enum.auto()

    #: Activity involving a uni-directional flow’s activity. Can contain wildcards.
    #: :currentmodule: zlogging.enum.NetControl
    EntityType['FLOW'] = enum.auto()

    #: Activity involving a MAC address.
    #: :currentmodule: zlogging.enum.NetControl
    EntityType['MAC'] = enum.auto()


@enum.unique
class RuleType(enum.IntFlag):
    """Type of rules that the framework supports. Each type lists the extra
    NetControl::Rule fields it uses, if any.

    Plugins may extend this type to define their own.

    c.f. `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html>`__

    """

    _ignore_ = 'RuleType _'
    RuleType = vars()

    #: Stop forwarding all packets matching the entity.
    #: No additional arguments.
    #: :currentmodule: zlogging.enum.NetControl
    RuleType['DROP'] = enum.auto()

    #: Modify all packets matching entity. The packets
    #: will be modified according to the mod entry of
    #: the rule.
    #: :currentmodule: zlogging.enum.NetControl
    RuleType['MODIFY'] = enum.auto()

    #: Redirect all packets matching entity to a different switch port,
    #: given in the out_port argument of the rule.
    #: :currentmodule: zlogging.enum.NetControl
    RuleType['REDIRECT'] = enum.auto()

    #: Whitelists all packets of an entity, meaning no restrictions will be applied.
    #: While whitelisting is the default if no rule matches, this type can be
    #: used to override lower-priority rules that would otherwise take effect for the
    #: entity.
    #: :currentmodule: zlogging.enum.NetControl
    RuleType['WHITELIST'] = enum.auto()


@enum.unique
class TargetType(enum.IntFlag):
    """Type defining the target of a rule.

    Rules can either be applied to the forward path, affecting all network traffic, or
    on the monitor path, only affecting the traffic that is sent to Zeek. The second
    is mostly used for shunting, which allows Zeek to tell the networking hardware that
    it wants to no longer see traffic that it identified as benign.

    c.f. `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html>`__

    """

    _ignore_ = 'TargetType _'
    TargetType = vars()

    #: :currentmodule: zlogging.enum.NetControl
    TargetType['FORWARD'] = enum.auto()

    #: :currentmodule: zlogging.enum.NetControl
    TargetType['MONITOR'] = enum.auto()


@enum.unique
class CatchReleaseActions(enum.IntFlag):
    """The enum that contains the different kinds of messages that are logged by
    catch and release.

    c.f. `policy/frameworks/netcontrol/catch-and-release.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/netcontrol/catch-and-release.zeek.html>`__

    """

    _ignore_ = 'CatchReleaseActions _'
    CatchReleaseActions = vars()

    #: Log lines marked with info are purely informational; no action was taken.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['INFO'] = enum.auto()

    #: A rule for the specified IP address already existed in NetControl (outside
    #: of catch-and-release). Catch and release did not add a new rule, but is now
    #: watching the IP address and will add a new rule after the current rule expires.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['ADDED'] = enum.auto()

    #: (present if base/frameworks/netcontrol/types.zeek is loaded)
    #: Stop forwarding all packets matching the entity.
    #: No additional arguments.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['DROP'] = enum.auto()

    #: A drop was requested by catch and release.
    #: An address was successfully blocked by catch and release.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['DROPPED'] = enum.auto()

    #: An address was unblocked after the timeout expired.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['UNBLOCK'] = enum.auto()

    #: An address was forgotten because it did not reappear within the watch_until interval.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['FORGOTTEN'] = enum.auto()

    #: A watched IP address was seen again; catch and release will re-block it.
    #: :currentmodule: zlogging.enum.NetControl
    CatchReleaseActions['SEEN_AGAIN'] = enum.auto()
