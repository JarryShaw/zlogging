# -*- coding: utf-8 -*-
# pylint: disable=all
# type: ignore

from typing import Any
import pytest

from zlogging.types import (AddrType, AnyType, BoolType, CountType, DoubleType, EnumType, IntervalType, IntType,
                            PortType, RecordType, SetType, StringType, SubnetType, TimeType, VectorType)


class TestAnyType:

    FIXTURES = [
        ('(empty)', '-', ','),
        (b'empty', b'+', b';'),
    ]

    @pytest.fixture(params=FIXTURES)
    def field(self, request):
        return AnyType(empty_field=request.param[0],
                       unset_field=request.param[1],
                       set_separator=request.param[2])

    def test_python_type(self, field: 'AnyType'):
        assert field.python_type == Any

    def test_zeek_type(self, field: 'AnyType'):
        assert field.zeek_type == 'any'

    def test_bro_type(self, field: 'AnyType'):
        assert field.bro_type == 'any'
