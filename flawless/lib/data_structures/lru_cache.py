#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# ---
# Author: John Egan <jwegan@gmail.com>

import collections
import time


def _now_seconds():
    return int(time.time())


class CacheEntry(object):

    def __init__(self, value):
        self.value = value
        self.last_update = _now_seconds()
        self.metadata = dict()  # Additional meta-data to store with the cache item

    def set_value(self, value):
        self.value = value
        self.last_update = _now_seconds()


class ExpiringLRUCache(object):
    """ Simple LRU cache with expiration time for data stored in the cache.

        size - max number of elements stored.
        expiration_seconds - how long we persist objects in the cache.
    """

    def __init__(self, size, expiration_seconds=None):
        """
        Args:
            ``size``: number of objects to to keep in cache
            ``expiration_seconds``: expiration time for cache in seconds. If None, then no expiration.
        """
        self.size = size
        self.expiration_seconds = expiration_seconds
        self.cache = collections.OrderedDict()

    def _mark_used(self, key):
        # Re-insertion takes advantage of OrderedDicts's ordering property to maintain LRU
        entry = self.cache.pop(key)
        if entry:
            self.cache[key] = entry

    def __setitem__(self, key, value):
        if key in self.cache:
            self._mark_used(key)
            self.cache[key].set_value(value)
            return

        if len(self.cache) >= self.size:
            self.cache.popitem(last=False)

        self.cache[key] = CacheEntry(value)

    def __getitem__(self, key):
        entry = self.cache.get(key)
        if not entry:
            return None

        if self.expiration_seconds and _now_seconds() >= entry.last_update + self.expiration_seconds:
            del self.cache[key]
            return None

        self._mark_used(key)
        return entry.value

    def __contains__(self, key):
        entry = self.cache.get(key)
        if not entry:
            return False

        if self.expiration_seconds and _now_seconds() >= entry.last_update + self.expiration_seconds:
            del self.cache[key]
            return False

        return True

    def __delitem__(self, key):
        del self.cache[key]

    def __len__(self):
        return len(self.cache)

    def get(self, key, default=None):
        return self[key] if key in self else default

    def clear(self):
        self.cache.clear()

    def get_cache_item_metadata(self, key, prop):
        if key in self.cache and prop in self.cache[key].metadata:
            return self.cache[key].metadata[prop]

    def set_cache_item_metadata(self, key, prop, value):
        if key in self.cache:
            self.cache[key].metadata[prop] = value
