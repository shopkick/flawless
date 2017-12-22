#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# ---
# Author: John Egan <jwegan@gmail.com>

import unittest
import sys

import flawless.lib.data_structures.lru_cache as lru_cache
from flawless.lib.data_structures.lru_cache import ExpiringLRUCache


class LRUCacheTestCase(unittest.TestCase):

    def setUp(self):
        super(LRUCacheTestCase, self).setUp()
        self.size = 5
        self.cache = ExpiringLRUCache(size=self.size)
        self.saved_now = lru_cache._now_seconds
        self.now_ts = 0
        lru_cache._now_seconds = lambda: self.now_ts

    def tearDown(self):
        lru_cache._now_seconds = self.saved_now

    def test_non_existent_key(self):
        self.assertEqual(None, self.cache.get("abc"))

    def test_purges_least_recently_used(self):
        for i in range(self.size + 1):
            self.cache[i] = "a"
        self.assertEqual(None, self.cache.get(0))

    def test_get_key(self):
        self.cache[1] = "a"
        self.assertEqual("a", self.cache[1])

    def test_bumps_recently_used(self):
        for i in range(2 * self.size):
            self.cache[i] = "a"
            self.cache[0] = "a"
        self.assertEqual("a", self.cache[0])

    def test_doesnt_expire_if_no_expiration(self):
        self.cache[1] = "a"
        self.now_ts = sys.maxsize
        self.assertEqual("a", self.cache[1])

    def test_expiration(self):
        self.cache = ExpiringLRUCache(size=self.size, expiration_seconds=1)
        self.cache[1] = "a"
        self.now_ts = 2
        self.assertEqual(None, self.cache.get(1))
