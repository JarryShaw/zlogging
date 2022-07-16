# -*- coding: utf-8 -*-
# pylint: disable=all
# type: ignore

import sys
from ctypes import c_int64, c_uint16, c_uint64
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Any, List, Set, Union

import pytest
from typing_inspect import typed_dict_keys

from zlogging._exc import ZeekTypeError, ZeekValueError, ZeekValueWarning
from zlogging.enum.zeek import Host

from zlogging.types import BaseType  # isort: split
from zlogging.types import (AddrType, AnyType, BoolType, CountType, DoubleType, EnumType,
                            IntervalType, IntType, PortType, RecordType, SetType, StringType,
                            SubnetType, TimeType, VectorType)

if sys.version_info[:2] < (3, 7):
    from aenum import Enum
else:
    from enum import Enum

if TYPE_CHECKING:
    from pytest import FixtureRequest

FIXTURES = [
    ('(empty)', '-', ',', {
        'empty_field': '(empty)',
        'unset_field': '-',
        'set_separator': ',',
    }),
    (b'[empty]', b'+', b';', {
        'empty_field': '[empty]',
        'unset_field': '+',
        'set_separator': ';',
    }),
]


class _SampleType(BaseType):

    @property
    def python_type(self):
        return 'python'

    @property
    def zeek_type(self):
        return 'zeek'

    def parse(self, data):
        return 'parse'

    def tojson(self, data):
        return 'json'

    def toascii(self, data):
        return 'ascii'


class TestBaseType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = _SampleType(empty_field=request.param[0],
                            unset_field=request.param[1],
                            set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: '_SampleType'):
        assert field.python_type == 'python'

    def test_zeek_type(self, field: '_SampleType'):
        assert field.zeek_type == 'zeek'

    def test_bro_type(self, field: '_SampleType'):
        with pytest.warns(DeprecationWarning):
            assert field.bro_type == 'zeek'

    def test_attributes(self, field: '_SampleType', expected):
        assert field.str_empty_field == expected['empty_field']
        assert field.str_unset_field == expected['unset_field']
        assert field.str_set_separator == expected['set_separator']

    def test_magic(self, field: '_SampleType', expected):
        # __call__
        assert field('test') == 'parse'
        assert field(None) == None

        # __str__
        assert str(field) == 'zeek'

        # __repr__
        assert repr(field) == '_SampleType(empty_field=%r, unset_field=%r, set_separator=%r)' % (
            expected['empty_field'], expected['unset_field'], expected['set_separator'],
        )


class TestAnyType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = AnyType(empty_field=request.param[0],
                        unset_field=request.param[1],
                        set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'AnyType'):
        assert field.python_type == Any

    def test_zeek_type(self, field: 'AnyType'):
        assert field.zeek_type == 'any'

    def test_parse(self, field: 'AnyType', expected):
        for data, expected in [
            (1, 1),
            ('test', 'test'),
            (b'test', b'test'),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

    def test_tojson(self, field: 'AnyType'):
        for data, expected in [
            (1, 1),
            ('test', 'test'),
            (b'test', {
                'data': "b'test'",
                'error': 'Object of type bytes is not JSON serializable',
            }),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'AnyType', expected):
        for data, expected in [
            (1, '1'),
            (None, expected['unset_field']),
            ('test', 'test'),
            (b'test', "b'test'"),
        ]:
            assert field.toascii(data) == expected


class TestBoolType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = BoolType(empty_field=request.param[0],
                         unset_field=request.param[1],
                         set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'BoolType'):
        assert field.python_type == bool

    def test_zeek_type(self, field: 'BoolType'):
        assert field.zeek_type == 'bool'

    def test_parse(self, field: 'BoolType', expected):
        for data, expected in [
            ('T', True),
            (b'T', True),
            ('F', False),
            (b'F', False),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

        with pytest.raises(ZeekValueError):
            field.parse('test')

    def test_tojson(self, field: 'BoolType'):
        for data, expected in [
            (True, True),
            (False, False),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'BoolType', expected):
        for data, expected in [
            (True, 'T'),
            (False, 'F'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestCountType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = CountType(empty_field=request.param[0],
                          unset_field=request.param[1],
                          set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'CountType'):
        assert field.python_type == c_uint64

    def test_zeek_type(self, field: 'CountType'):
        assert field.zeek_type == 'count'

    def test_parse(self, field: 'CountType', expected):
        assert field.parse(expected['unset_field']) == None
        for data, expected in [
            (c_uint64(1), 1),
            ('1', 1),
            (b'1', 1),
            (1, 1),
        ]:
            assert field.parse(data).value == expected

    def test_tojson(self, field: 'CountType'):
        for data, expected in [
            (c_uint64(1), 1),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'CountType', expected):
        for data, expected in [
            (c_uint64(1), '1'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestIntType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = IntType(empty_field=request.param[0],
                        unset_field=request.param[1],
                        set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'IntType'):
        assert field.python_type == c_int64

    def test_zeek_type(self, field: 'IntType'):
        assert field.zeek_type == 'int'

    def test_parse(self, field: 'IntType', expected):
        assert field.parse(expected['unset_field']) == None
        for data, expected in [
            (c_int64(1), 1),
            ('1', 1),
            (b'1', 1),
            (1, 1),
        ]:
            assert field.parse(data).value == expected

    def test_tojson(self, field: 'IntType'):
        for data, expected in [
            (c_int64(1), 1),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'IntType', expected):
        for data, expected in [
            (c_int64(1), '1'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestDoubleType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = DoubleType(empty_field=request.param[0],
                           unset_field=request.param[1],
                           set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'DoubleType'):
        assert field.python_type == Decimal

    def test_zeek_type(self, field: 'DoubleType'):
        assert field.zeek_type == 'double'

    def test_parse(self, field: 'DoubleType', expected):
        with localcontext() as ctx:
            ctx.prec = 6
            one = Decimal(1)
            for data, expected in [
                (Decimal(1), one),
                ('1', one),
                (b'1', one),
                (expected['unset_field'], None),
            ]:
                assert field.parse(data) == expected

    def test_tojson(self, field: 'DoubleType'):
        for data, expected in [
            (Decimal(1), 1),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'DoubleType', expected):
        for data, expected in [
            (Decimal(1), '1.000000'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestTimeType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = TimeType(empty_field=request.param[0],
                         unset_field=request.param[1],
                         set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'TimeType'):
        assert field.python_type == datetime

    def test_zeek_type(self, field: 'TimeType'):
        assert field.zeek_type == 'time'

    def test_parse(self, field: 'TimeType', expected):
        now = datetime(2021, 1, 25, 13, 5, 47, 490889)
        timestamp = now.timestamp()
        for data, expected in [
            (now, now),
            (timestamp, now),
            (str(timestamp), now),
            (str(timestamp).encode('ascii'), now),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

    def test_tojson(self, field: 'TimeType'):
        now = datetime(2021, 1, 25, 13, 5, 47, 490889)
        timestamp = now.timestamp()
        for data, expected in [
            (now, timestamp),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'TimeType', expected):
        now = datetime(2021, 1, 25, 13, 5, 47, 490889)
        timestamp = now.timestamp()
        for data, expected in [
            (now, str(timestamp)),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestIntervalType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = IntervalType(empty_field=request.param[0],
                             unset_field=request.param[1],
                             set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'IntervalType'):
        assert field.python_type == timedelta

    def test_zeek_type(self, field: 'IntervalType'):
        assert field.zeek_type == 'interval'

    def test_parse(self, field: 'IntervalType', expected):
        diff = timedelta(days=1, seconds=2, milliseconds=34, microseconds=10)
        for data, expected in [
            (diff, diff),
            ('86402.03401', diff),
            (b'86402.034010', diff),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

    def test_tojson(self, field: 'IntervalType'):
        diff = timedelta(days=1, seconds=2, milliseconds=34, microseconds=10)
        for data, expected in [
            (diff, 86402.03401),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'IntervalType', expected):
        diff = timedelta(days=1, seconds=2, milliseconds=34, microseconds=10)
        for data, expected in [
            (diff, '86402.034010'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestStringType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = StringType(empty_field=request.param[0],
                           unset_field=request.param[1],
                           set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'StringType'):
        assert field.python_type == Union[bytes, memoryview, bytearray]

    def test_zeek_type(self, field: 'StringType'):
        assert field.zeek_type == 'string'

    def test_parse(self, field: 'StringType', expected):
        for data, expected in [
            (b'test', b'test'),
            ('test', b'test'),
            (bytearray(b'test'), b'test'),
            (memoryview(b'test'), b'test'),
            (expected['empty_field'], b''),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

    def test_tojson(self, field: 'StringType'):
        for data, expected in [
            (b'test', 'test'),
            (bytearray(b'test'), 'test'),
            (memoryview(b'test'), 'test'),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'StringType', expected):
        for data, expected in [
            (b'test', 'test'),
            (bytearray(b'test'), 'test'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestAddrType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = AddrType(empty_field=request.param[0],
                         unset_field=request.param[1],
                         set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'AddrType'):
        assert field.python_type == Union[IPv4Address, IPv6Address]

    def test_zeek_type(self, field: 'AddrType'):
        assert field.zeek_type == 'addr'

    def test_parse(self, field: 'AddrType', expected):
        v4 = IPv4Address('127.0.0.1')
        v6 = IPv6Address('::1')
        for data, expected in [
            (v4, v4),
            (v6, v6),
            ('127.0.0.1', v4),
            (b'::1', v6),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

    def test_tojson(self, field: 'AddrType'):
        v4 = IPv4Address('127.0.0.1')
        v6 = IPv6Address('::1')
        for data, expected in [
            (v4, '127.0.0.1'),
            (v6, '::1'),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'AddrType', expected):
        v4 = IPv4Address('127.0.0.1')
        v6 = IPv6Address('::1')
        for data, expected in [
            (v4, '127.0.0.1'),
            (v6, '::1'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestPortType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = PortType(empty_field=request.param[0],
                         unset_field=request.param[1],
                         set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'PortType'):
        assert field.python_type == c_uint16

    def test_zeek_type(self, field: 'PortType'):
        assert field.zeek_type == 'port'

    def test_parse(self, field: 'IntType', expected):
        assert field.parse(expected['unset_field']) == None
        for data, expected in [
            (c_uint16(1), 1),
            ('1', 1),
            (b'1', 1),
            (1, 1),
        ]:
            assert field.parse(data).value == expected

    def test_tojson(self, field: 'IntType'):
        for data, expected in [
            (c_uint16(1), 1),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'IntType', expected):
        for data, expected in [
            (c_uint16(1), '1'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestSubnetType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = SubnetType(empty_field=request.param[0],
                           unset_field=request.param[1],
                           set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'SubnetType'):
        assert field.python_type == Union[IPv4Network, IPv6Network]

    def test_zeek_type(self, field: 'SubnetType'):
        assert field.zeek_type == 'subnet'

    def test_parse(self, field: 'SubnetType', expected):
        v4 = IPv4Network('192.168.0.0/24')
        v6 = IPv6Network('2001:db8::1000/124')
        for data, expected in [
            (v4, v4),
            (v6, v6),
            ('192.168.0.0/24', v4),
            (b'2001:db8::1000/124', v6),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

    def test_tojson(self, field: 'SubnetType'):
        v4 = IPv4Network('192.168.0.0/24')
        v6 = IPv6Network('2001:db8::1000/124')
        for data, expected in [
            (v4, '192.168.0.0/24'),
            (v6, '2001:db8::1000/124'),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'SubnetType', expected):
        v4 = IPv4Network('192.168.0.0/24')
        v6 = IPv6Network('2001:db8::1000/124')
        for data, expected in [
            (v4, '192.168.0.0/24'),
            (v6, '2001:db8::1000/124'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestEnumType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = EnumType(empty_field=request.param[0],
                         unset_field=request.param[1],
                         set_separator=request.param[2])
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'EnumType'):
        assert field.python_type == Enum

    def test_zeek_type(self, field: 'EnumType'):
        assert field.zeek_type == 'enum'

    def test_attributes(self, field: 'EnumType'):
        assert field.enum_namespaces['ALL_HOSTS'] == Host['ALL_HOSTS']

    def test_parse(self, field: 'EnumType', expected):
        enum = Host['ALL_HOSTS']
        for data, expected in [
            (enum, enum),
            ('ALL_HOSTS', enum),
            (b'ALL_HOSTS', enum),
            (expected['unset_field'], None),
        ]:
            assert field.parse(data) == expected

        with pytest.warns(ZeekValueWarning):
            assert field.parse('FOO_BAR').name == 'FOO_BAR'

    def test_tojson(self, field: 'EnumType'):
        enum = Host['ALL_HOSTS']
        for data, expected in [
            (enum, 'ALL_HOSTS'),
            (None, None),
        ]:
            assert field.tojson(data) == expected

    def test_toascii(self, field: 'EnumType', expected):
        enum = Host['ALL_HOSTS']
        for data, expected in [
            (enum, 'ALL_HOSTS'),
            (None, expected['unset_field']),
        ]:
            assert field.toascii(data) == expected


class TestSetType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = SetType(empty_field=request.param[0],
                        unset_field=request.param[1],
                        set_separator=request.param[2],
                        element_type=StringType(empty_field=request.param[0],
                                                unset_field=request.param[1],
                                                set_separator=request.param[2]))
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'SetType'):
        assert field.python_type == Set[Union[bytes, memoryview, bytearray]]

    def test_zeek_type(self, field: 'SetType'):
        assert field.zeek_type == 'set[string]'

    def test_magic(self):
        # __init__
        with pytest.raises(ZeekTypeError):
            SetType()

        with pytest.raises(ZeekValueError):
            SetType(element_type=str)

        assert SetType(element_type=StringType).zeek_type == 'set[string]'

    def test_attributes(self, field: 'SetType'):
        assert field.element_type.zeek_type == 'string'

    def test_parse(self, field: 'SetType', expected):
        assert field.parse(expected['unset_field']) == None
        assert field.parse(expected['empty_field']) == set()

        assert field.parse({'a', b'b', memoryview(b'c')}) == {b'a', b'b', b'c'}
        assert field.parse(expected['set_separator'].join(['a', 'b', 'c'])) == {b'a', b'b', b'c'}

    def test_tojson(self, field: 'SetType'):
        assert field.tojson(None) == None
        assert field.tojson({b'a', b'b', memoryview(b'c')}) == ['a', 'b', 'c']

    def test_toascii(self, field: 'SetType', expected):
        assert field.toascii(None) == expected['unset_field']
        assert field.toascii(set()) == expected['empty_field']
        assert field.toascii({b'a', b'b', memoryview(b'c')}) == expected['set_separator'].join(['a', 'b', 'c'])


class TestVectorType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = VectorType(empty_field=request.param[0],
                        unset_field=request.param[1],
                        set_separator=request.param[2],
                        element_type=StringType(empty_field=request.param[0],
                                                unset_field=request.param[1],
                                                set_separator=request.param[2]))
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'VectorType'):
        assert field.python_type == List[Union[bytes, memoryview, bytearray]]

    def test_zeek_type(self, field: 'VectorType'):
        assert field.zeek_type == 'vector[string]'

    def test_magic(self):
        # __init__
        with pytest.raises(ZeekTypeError):
            VectorType()

        with pytest.raises(ZeekValueError):
            VectorType(element_type=str)

        assert VectorType(element_type=StringType).zeek_type == 'vector[string]'

    def test_attributes(self, field: 'VectorType'):
        assert field.element_type.zeek_type == 'string'

    def test_parse(self, field: 'VectorType', expected):
        assert field.parse(expected['unset_field']) == None
        assert field.parse(expected['empty_field']) == []

        assert field.parse(['a', b'b', bytearray(b'c'), memoryview(b'd')]) == [b'a', b'b', b'c', b'd']
        assert field.parse(expected['set_separator'].join(['a', 'b', 'c'])) == [b'a', b'b', b'c']

    def test_tojson(self, field: 'VectorType'):
        assert field.tojson(None) == None
        assert field.tojson([b'a', bytearray(b'b'), memoryview(b'c')]) == ['a', 'b', 'c']

    def test_toascii(self, field: 'VectorType', expected):
        assert field.toascii(None) == expected['unset_field']
        assert field.toascii([]) == expected['empty_field']
        assert field.toascii([b'a', bytearray(b'b'), memoryview(b'c')]) == expected['set_separator'].join(['a', 'b', 'c'])


class TestRecordType:

    @pytest.fixture(params=FIXTURES)
    def field(self, request: 'FixtureRequest'):
        field = RecordType(empty_field=request.param[0],
                           unset_field=request.param[1],
                           set_separator=request.param[2],
                           foo=StringType(
            empty_field=request.param[0],
            unset_field=request.param[1],
            set_separator=request.param[2],
        ),
            bar=CountType(
            empty_field=request.param[0],
            unset_field=request.param[1],
            set_separator=request.param[2],
        ))
        request.keywords['expected'] = request.param[3]
        return field

    @pytest.fixture()
    def expected(self, request: 'FixtureRequest', field):
        return request.keywords['expected']

    def test_python_type(self, field: 'RecordType'):
        assert typed_dict_keys(field.python_type) == {
            'foo': Union[bytes, memoryview, bytearray],
            'bar': c_uint64,
        }

    def test_zeek_type(self, field: 'RecordType'):
        assert field.zeek_type == 'record'

    def test_magic(self):
        # __init__
        with pytest.raises(ZeekValueError):
            RecordType(empty_field='(empty)', foo=StringType(empty_field='[empty]'))
        with pytest.raises(ZeekValueError):
            class Record(RecordType):
                foo = StringType(empty_field='[empty]')
            Record(empty_field='(empty)')

        with pytest.raises(ZeekValueError):
            Record(foo=str)

        assert RecordType(foo=StringType).element_mapping['foo'].zeek_type == 'string'

    def test_attributes(self, field: 'RecordType'):
        assert field.element_mapping['foo'].zeek_type == 'string'
