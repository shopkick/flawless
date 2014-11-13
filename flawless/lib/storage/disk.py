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

import os

import flawless.lib.config
from flawless.lib.data_structures.persistent_dictionary import PersistentDictionary
from flawless.lib.storage import StorageInterface


class DiskStorage(StorageInterface):

    def __init__(self, partition):
        super(DiskStorage, self).__init__(partition)
        config = flawless.lib.config.get()
        if self.partition:
            filepath = os.path.join(config.data_dir_path, "flawless-errors-", partition)
        else:
            filepath = os.path.join(config.data_dir_path, "flawless-whitelists-config")
        self.disk_dict = PersistentDictionary(filepath)

    def _proxyfunc_(attr, self, *args, **kwargs):
        try:
            return getattr(self.disk_dict, attr)(*args, **kwargs)
        except KeyError:
            return None

    def open(self):
        self.disk_dict.open()

        # Build new copy of dict since migrate_thrift_obj may change the hash code of the keys of the dict
        migrated_dict = dict()
        for key, value in self.disk_dict.dict.items():
            self.migrate_thrift_obj(key)
            self.migrate_thrift_obj(value)
            migrated_dict[key] = value

        self.disk_dict.dict = migrated_dict

    def sync(self):
        self.disk_dict.sync()

    def close(self):
        self.disk_dict.close()

    def iteritems(self):
        return self.disk_dict.dict.iteritems()

    def __setitem__(self, key, item):
        self.disk_dict[key] = item

    def __getitem__(self, key):
        try:
            return self.disk_dict[key]
        except KeyError:
            return None

    def __contains__(self, key):
        return key in self.disk_dict
