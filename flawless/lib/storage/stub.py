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

from flawless.lib.storage import StorageInterface


class StubStorage(StorageInterface):

    def __init__(self, partition):
        self.partition = partition
        self.dict = dict()

    def iteritems(self):
        return self.dict.iteritems()

    def __setitem__(self, key, item):
        self.dict[key] = item

    def __getitem__(self, key):
        return self.dict.get(key)

    def __contains__(self, key):
        return key in self.dict
