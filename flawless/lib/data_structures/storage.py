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
# Author: John Egan <john@shopkick.com>

import abc
import os.path

import flawless.lib.config
from flawless.lib.data_structures import ProxyContainerMethodsMetaClass
from flawless.lib.data_structures.persistent_dictionary import PersistentDictionary


class StorageInterface(object):
    """By default Flawless stores everything on disk which means there can only be one centralized instance of
    Flawless. You can implement your own instance of StorageInterface that connects to a backend database and pass
    it into flawless.server.server.serve. Then it is possible to have the flawless server be horizontally scalable
    since the database serves as the centralized source of truth.

    It is worth noting is that the keys used in this interface are instances of api_ttypes.ErrorKey and the
    values are instances of api_ttypes.ErrorInfo
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, week_prefix):
        """week_prefix is a string used to partition keys by week. For instance, with disk storage, we create a new
        file for every unique week_prefix. For a database you may want to consider prepending all keys with
        week_prefix."""
        self.week_prefix = week_prefix

    def open(self):
        """Called to create connection to storage"""
        pass

    def sync(self):
        """Called periodically to flush data"""
        pass

    def close(self):
        """Called to close connection to storage"""
        pass

    @abc.abstractmethod
    def iteritems(self):
        """Should return iterator of tuples (key, value) for all entries for the given self.week_prefix"""
        pass

    @abc.abstractmethod
    def __setitem__(self, key, item):
        pass

    @abc.abstractmethod
    def __getitem__(self, key):
        """Should raise KeyError if key does not exist"""
        pass

    @abc.abstractmethod
    def __contains__(self, key):
        pass


class DiskStorage(object):

    __metaclass__ = ProxyContainerMethodsMetaClass

    def __init__(self, week_prefix):
        self.week_prefix = week_prefix
        config = flawless.lib.config.get()
        filepath = os.path.join(config.data_dir_path, "flawless-errors-", week_prefix)
        self.disk_dict = PersistentDictionary(filepath)

    def _proxyfunc_(attr, self, *args, **kwargs):
        return getattr(self.disk_dict, attr)(*args, **kwargs)

    def open(self):
        self.disk_dict.open()

    def sync(self):
        self.disk_dict.sync()

    def close(self):
        self.disk_dict.close()

    def iteritems(self):
        return self.disk_dict.dict.iteritems()

StorageInterface.register(DiskStorage)
