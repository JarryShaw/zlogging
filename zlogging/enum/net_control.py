# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``NetControl``."""

from zlogging._compat import enum


@enum.unique
class InfoCategory(enum.IntFlag):
    """Enum: ``NetControl::InfoCategory``.

    Type of an entry in the NetControl log.

    See Also:
        `base/frameworks/netcontrol/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/main.zeek.html#type-NetControl::InfoCategory>`__

    """

    _ignore_ = 'InfoCategory _'
    InfoCategory = vars()

    #: A log entry reflecting a framework message.
    MESSAGE = enum.auto()

    #: A log entry reflecting a framework message.
    ERROR = enum.auto()

    #: A log entry about a rule.
    RULE = enum.auto()


@enum.unique
class InfoState(enum.IntFlag):
    """Enum: ``NetControl::InfoState``.

    State of an entry in the NetControl log.

    See Also:
        `base/frameworks/netcontrol/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/main.zeek.html#type-NetControl::InfoState>`__

    """

    _ignore_ = 'InfoState _'
    InfoState = vars()

    #: The request to add/remove a rule was sent to the respective backend.
    REQUESTED = enum.auto()

    #: A rule was successfully added by a backend.
    SUCCEEDED = enum.auto()

    #: A backend reported that a rule was already existing.
    EXISTS = enum.auto()

    #: A rule addition failed.
    FAILED = enum.auto()

    #: A rule was successfully removed by a backend.
    REMOVED = enum.auto()

    #: A rule timeout was triggered by the NetControl framework or a backend.
    TIMEOUT = enum.auto()


@enum.unique
class EntityType(enum.IntFlag):
    """Enum: ``NetControl::EntityType``.

    Type defining the entity that a rule applies to.

    See Also:
        `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html#type-NetControl::EntityType>`__

    """

    _ignore_ = 'EntityType _'
    EntityType = vars()

    #: Activity involving a specific IP address.
    ADDRESS = enum.auto()

    #: Activity involving all of a bi-directional connection’s activity.
    CONNECTION = enum.auto()

    #: Activity involving a uni-directional flow’s activity. Can contain wildcards.
    FLOW = enum.auto()

    #: Activity involving a MAC address.
    MAC = enum.auto()


@enum.unique
class RuleType(enum.IntFlag):
    """Enum: ``NetControl::RuleType``.

    Type of rules that the framework supports. Each type lists the extra ``NetControl::Rule`` fields it
    uses, if any.

    Plugins may extend this type to define their own.

    See Also:
        `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html#type-NetControl::RuleType>`__

    """

    _ignore_ = 'RuleType _'
    RuleType = vars()

    #: Stop forwarding all packets matching the entity.
    #: No additional arguments.
    DROP = enum.auto()

    #: Modify all packets matching entity. The packets
    #: will be modified according to the mod entry of
    #: the rule.
    MODIFY = enum.auto()

    #: Redirect all packets matching entity to a different switch port,
    #: given in the out\_port argument of the rule.
    REDIRECT = enum.auto()

    #: Whitelists all packets of an entity, meaning no restrictions will be applied.
    #: While whitelisting is the default if no rule matches, this type can be
    #: used to override lower-priority rules that would otherwise take effect for the
    #: entity.
    WHITELIST = enum.auto()


@enum.unique
class TargetType(enum.IntFlag):
    """Enum: ``NetControl::TargetType``.

    Type defining the target of a rule.

    Rules can either be applied to the forward path, affecting all network traffic, or on the monitor
    path, only affecting the traffic that is sent to Zeek. The second is mostly used for shunting, which
    allows Zeek to tell the networking hardware that it wants to no longer see traffic that it
    identified as benign.

    See Also:
        `base/frameworks/netcontrol/types.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/netcontrol/types.zeek.html#type-NetControl::TargetType>`__

    """

    _ignore_ = 'TargetType _'
    TargetType = vars()

    FORWARD = enum.auto()

    MONITOR = enum.auto()


@enum.unique
class CatchReleaseActions(enum.IntFlag):
    """Enum: ``NetControl::CatchReleaseActions``.

    The enum that contains the different kinds of messages that are logged by catch and release.

    See Also:
        `policy/frameworks/netcontrol/catch-and-release.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/netcontrol/catch-and-release.zeek.html#type-NetControl::CatchReleaseActions>`__

    """

    _ignore_ = 'CatchReleaseActions _'
    CatchReleaseActions = vars()

    #: Log lines marked with info are purely informational; no action was taken.
    INFO = enum.auto()

    #: A rule for the specified IP address already existed in NetControl (outside
    #: of catch-and-release). Catch and release did not add a new rule, but is now
    #: watching the IP address and will add a new rule after the current rule expires.
    ADDED = enum.auto()

    #: A drop was requested by catch and release.
    DROP_REQUESTED = enum.auto()

    #: An address was successfully blocked by catch and release.
    DROPPED = enum.auto()

    #: An address was unblocked after the timeout expired.
    UNBLOCK = enum.auto()

    #: An address was forgotten because it did not reappear within the watch\_until interval.
    FORGOTTEN = enum.auto()

    #: A watched IP address was seen again; catch and release will re-block it.
    SEEN_AGAIN = enum.auto()
