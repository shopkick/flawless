#!/usr/bin/env python
#
# Copyright (c) 2011-2013, Shopkick Inc.
# All rights reserved.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# ---
# Author: John Egan <jwegan@gmail.com>

from __future__ import absolute_import
import cPickle as pickle

import redis  # Tested with redis==2.4.10

import flawless.lib.config
from flawless.lib.storage import StorageInterface


class RedisStorage(StorageInterface):

    def __init__(self, host, port, partition, socket_timeout=2):
        super(RedisStorage, self).__init__(partition=partition)
        self.redis_partition_name = self.partition if self.partition else "config"
        self.client = redis.Redis(host=host, port=port, socket_timeout=socket_timeout)
        config = flawless.lib.config.get()
        self.redis_version = config.redis_version

    def _serialize(self, value):
        return pickle.dumps(value, pickle.HIGHEST_PROTOCOL)

    def _deserialize(self, data):
        if data is None:
            return None
        obj = pickle.loads(data)
        self.migrate_thrift_obj(obj)
        return obj

    def _hscan_iter(self, name):
        if hasattr(self.client, "hscan_iter") and self.redis_version >= '2.8':
            for key, value in self.client.hscan_iter(name):
                yield (key, value)
            return
        else:
            for key, value in self.client.hgetall(name).iteritems():
                yield (key, value)
            return

    def iteritems(self):
        for key, value in self._hscan_iter(self.redis_partition_name):
            key = self._deserialize(key)
            value = self._deserialize(value)
            yield (key, value)

    def __setitem__(self, key, item):
        self.client.hset(self.redis_partition_name, self._serialize(key), self._serialize(item))

    def __getitem__(self, key):
        data = self.client.hget(self.redis_partition_name, self._serialize(key))
        return self._deserialize(data)

    def __contains__(self, key):
        return self.client.hexists(self.redis_partition_name, self._serialize(key))
