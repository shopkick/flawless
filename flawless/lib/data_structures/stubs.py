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

from flawless.lib.data_structures import ProxyContainerMethodsMetaClass
from flawless.lib.storage import StorageInterface


class StorageStub(object):

    __metaclass__ = ProxyContainerMethodsMetaClass

    def _proxyfunc_(attr, self, *args, **kwargs):
        try:
            return getattr(self.dict, attr)(*args, **kwargs)
        except KeyError:
            return None

    def __init__(self, partition):
        self.partition = partition
        self.dict = dict()

    def iteritems(self):
        return self.dict.iteritems()

    def open(self):
        pass

    def sync(self):
        pass

    def close(self):
        pass

StorageInterface.register(StorageStub)
