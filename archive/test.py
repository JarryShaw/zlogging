# -*- coding: utf-8 -*-
"""Unittest cases."""

import os
import unittest

import zlogging  # pylint: disable=import-error

ROOT = os.path.dirname(os.path.realpath(__file__))


class TestZLogging(unittest.TestCase):
    """Test ZLogging."""

    maxDiff = None

    def test_load(self):
        with open(os.path.join(ROOT, 'logs', 'http.log'), 'rb') as file:
            info = zlogging.load(file)
        self.assertEqual(info.format, 'ascii')


if __name__ == "__main__":
    unittest.main()
