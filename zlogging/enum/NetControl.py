# -*- coding: utf-8 -*-
"""Namespace: ``NetControl``."""

from zlogging._compat import enum


@enum.unique
class InfoCategory(enum.IntFlag):
    """Type of an entry in the NetControl log.

    c.f. `base/frameworks/netcontrol/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/main.zeek.html#type-NetControl::InfoCategory>`__

    """

    _ignore_ = 'InfoCategory _'
    InfoCategory = vars()

    #: A log entry reflecting a framework message.
    InfoCategory['MESSAGE'] = enum.auto()

    #: A log entry reflecting a framework message.
    InfoCategory['ERROR'] = enum.auto()

    #: A log entry about a rule.
    InfoCategory['RULE'] = enum.auto()


@enum.unique
class InfoState(enum.IntFlag):
    """State of an entry in the NetControl log.

    c.f. `base/frameworks/netcontrol/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/main.zeek.html#type-NetControl::InfoState>`__

    """

    _ignore_ = 'InfoState _'
    InfoState = vars()

    #: The request to add/remove a rule was sent to the respective backend.
    InfoState['REQUESTED'] = enum.auto()

    #: A rule was successfully added by a backend.
    InfoState['SUCCEEDED'] = enum.auto()

    #: A backend reported that a rule was already existing.
    InfoState['EXISTS'] = enum.auto()

    #: A rule addition failed.
    InfoState['FAILED'] = enum.auto()

    #: A rule was successfully removed by a backend.
    InfoState['REMOVED'] = enum.auto()

    #: A rule timeout was triggered by the NetControl framework or a backend.
    InfoState['TIMEOUT'] = enum.auto()


@enum.unique
class EntityType(enum.IntFlag):
    """Type defining the entity that a rule applies to.

    c.f. `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html#type-NetControl::EntityType>`__

    """

    _ignore_ = 'EntityType _'
    EntityType = vars()

    #: Activity involving a specific IP address.
    EntityType['ADDRESS'] = enum.auto()

    #: Activity involving all of a bi-directional connection’s activity.
    EntityType['CONNECTION'] = enum.auto()

    #: Activity involving a uni-directional flow’s activity. Can contain wildcards.
    EntityType['FLOW'] = enum.auto()

    #: Activity involving a MAC address.
    EntityType['MAC'] = enum.auto()


@enum.unique
class RuleType(enum.IntFlag):
    """Type of rules that the framework supports. Each type lists the extra
    NetControl::Rule fields it uses, if any.

    Plugins may extend this type to define their own.

    c.f. `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html#type-NetControl::RuleType>`__

    """

    _ignore_ = 'RuleType _'
    RuleType = vars()

    #: Stop forwarding all packets matching the entity.
    #: No additional arguments.
    RuleType['DROP'] = enum.auto()

    #: Modify all packets matching entity. The packets
    #: will be modified according to the mod entry of
    #: the rule.
    RuleType['MODIFY'] = enum.auto()

    #: Redirect all packets matching entity to a different switch port,
    #: given in the out\_port argument of the rule.
    RuleType['REDIRECT'] = enum.auto()

    #: Whitelists all packets of an entity, meaning no restrictions will be applied.
    #: While whitelisting is the default if no rule matches, this type can be
    #: used to override lower-priority rules that would otherwise take effect for the
    #: entity.
    RuleType['WHITELIST'] = enum.auto()


@enum.unique
class TargetType(enum.IntFlag):
    """Type defining the target of a rule.

    Rules can either be applied to the forward path, affecting all network traffic, or
    on the monitor path, only affecting the traffic that is sent to Zeek. The second
    is mostly used for shunting, which allows Zeek to tell the networking hardware that
    it wants to no longer see traffic that it identified as benign.

    c.f. `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html#type-NetControl::TargetType>`__

    """

    _ignore_ = 'TargetType _'
    TargetType = vars()

    TargetType['FORWARD'] = enum.auto()

    TargetType['MONITOR'] = enum.auto()


@enum.unique
class CatchReleaseActions(enum.IntFlag):
    """The enum that contains the different kinds of messages that are logged by
    catch and release.

    c.f. `policy/frameworks/netcontrol/catch-and-release.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/netcontrol/catch-and-release.zeek.html#type-NetControl::CatchReleaseActions>`__

    """

    _ignore_ = 'CatchReleaseActions _'
    CatchReleaseActions = vars()

    #: Log lines marked with info are purely informational; no action was taken.
    CatchReleaseActions['INFO'] = enum.auto()

    #: A rule for the specified IP address already existed in NetControl (outside
    #: of catch-and-release). Catch and release did not add a new rule, but is now
    #: watching the IP address and will add a new rule after the current rule expires.
    CatchReleaseActions['ADDED'] = enum.auto()

    #: (present if base/frameworks/netcontrol/types.zeek is loaded)
    #: Stop forwarding all packets matching the entity.
    #: No additional arguments.
    CatchReleaseActions['DROP'] = enum.auto()

    #: A drop was requested by catch and release.
    #: An address was successfully blocked by catch and release.
    CatchReleaseActions['DROPPED'] = enum.auto()

    #: An address was unblocked after the timeout expired.
    CatchReleaseActions['UNBLOCK'] = enum.auto()

    #: An address was forgotten because it did not reappear within the watch\_until interval.
    CatchReleaseActions['FORGOTTEN'] = enum.auto()

    #: A watched IP address was seen again; catch and release will re-block it.
    CatchReleaseActions['SEEN_AGAIN'] = enum.auto()
