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
import os.path
import cPickle as pickle
import shutil
import threading

from flawless.lib.data_structures import ProxyContainerMethodsMetaClass


class PersistentDictionary(object):
    ''' Provides a persistent thread-safe dictionary that is backed by a file on disk '''
    __metaclass__ = ProxyContainerMethodsMetaClass

    def _proxyfunc_(attr, self, *args, **kwargs):
        with self.lock:
            return getattr(self.dict, attr)(*args, **kwargs)

    def __init__(self, file_path):
        self.lock = threading.RLock()
        self.file_path = file_path
        self.dict = None

    def open(self):
        with self.lock:
            if os.path.isfile(self.file_path):
                fh = open(self.file_path, "rb+")
                self.dict = pickle.load(fh)
                fh.close()
            else:
                self.dict = dict()

    def sync(self):
        with self.lock:
            fh = open(self.file_path + ".tmp", "wb+")
            pickle.dump(self.dict, fh, pickle.HIGHEST_PROTOCOL)
            fh.close()
            shutil.move(self.file_path + ".tmp", self.file_path)

    def close(self):
        pass

    def get_path(self):
        return self.file_path
