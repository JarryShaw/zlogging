# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Management``."""

from zlogging._compat import enum


@enum.unique
class Role(enum.IntFlag):
    """Enum: ``Management::Role``.

    Management infrastructure node type. This intentionally does not include the managed cluster node
    types (worker, logger, etc) – those continue to be managed by the cluster framework.

    See Also:
        `policy/frameworks/management/types.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/management/types.zeek.html#type-Management::Role>`__

    """

    _ignore_ = 'Role _'
    Role = vars()

    #: No active role in cluster management
    NONE = enum.auto()

    #: A cluster management agent.
    AGENT = enum.auto()

    #: The cluster’s controller.
    CONTROLLER = enum.auto()

    #: A managed cluster node (worker, manager, etc).
    NODE = enum.auto()


@enum.unique
class State(enum.IntFlag):
    """Enum: ``Management::State``.

    State that a Cluster Node can be in. State changes trigger an API notification (see
    notify_change()). The Pending state corresponds to the Supervisor not yet reporting a PID for a node
    when it has not yet fully launched.

    See Also:
        `policy/frameworks/management/types.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/management/types.zeek.html#type-Management::State>`__

    """

    _ignore_ = 'State _'
    State = vars()

    #: Not yet running
    PENDING = enum.auto()

    #: Running and operating normally
    RUNNING = enum.auto()

    #: Explicitly stopped
    STOPPED = enum.auto()

    #: Failed to start; and permanently halted
    FAILED = enum.auto()

    #: Crashed, will be restarted,
    CRASHED = enum.auto()

    #: State not known currently (e.g., because of lost connectivity)
    UNKNOWN = enum.auto()
