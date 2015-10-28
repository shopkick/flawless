#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# ---
# Author: John Egan <jwegan@gmail.com>

import unittest

from flawless.lib.data_structures.lru_cache import LRUCache


class LRUCacheTestCase(unittest.TestCase):

    def setUp(self):
        super(LRUCacheTestCase, self).setUp()
        self.size = 5
        self.cache = LRUCache(size=self.size)

    def test_non_existent_key(self):
        self.assertEquals(None, self.cache.get("abc"))

    def test_purges_least_recently_used(self):
        for i in range(self.size + 1):
            self.cache[i] = "a"
        self.assertEquals(None, self.cache.get(0))

    def test_get_key(self):
        self.cache[1] = "a"
        self.assertEquals("a", self.cache[1])

    def test_bumps_recently_used(self):
        for i in range(2 * self.size):
            self.cache[i] = "a"
            self.cache[0] = "a"
        self.assertEquals("a", self.cache[0])
