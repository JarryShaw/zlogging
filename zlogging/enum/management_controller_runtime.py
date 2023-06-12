# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``Management::Controller::Runtime``."""

from zlogging._compat import enum


@enum.unique
class ConfigState(enum.IntFlag):
    """Enum: ``Management::Controller::Runtime::ConfigState``.

    A cluster configuration uploaded by the client goes through multiple states on its way to
    deployment.

    See Also:
        `policy/frameworks/management/controller/main.zeek <https://docs.zeek.org/en/stable/scripts/policy/frameworks/management/controller/main.zeek.html#type-Management::Controller::Runtime::ConfigState>`__

    """

    _ignore_ = 'ConfigState _'
    ConfigState = vars()

    #: As provided by the client.
    STAGED = enum.auto()

    #: Necessary updates made, e.g. ports filled in.
    READY = enum.auto()

    #: Sent off to the agents for deployment.
    DEPLOYED = enum.auto()
