#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# ---
# Author: John Egan <jwegan@gmail.com>

import collections

from flawless.lib.data_structures import ProxyContainerMethodsMetaClass


class LRUCache(object):
    __metaclass__ = ProxyContainerMethodsMetaClass
    _proxyfunc_ = lambda attr, self, *args, **kwargs: getattr(self.cache, attr)(*args, **kwargs)
    _proxyfunc_func_set_ = set(['__getitem__', '__contains__', '__delitem__', '__len__', 'get'])

    def __init__(self, size):
        self.size = size
        self.cache = collections.OrderedDict()

    def __setitem__(self, key, value):
        if key in self.cache:
            del self.cache[key]
        if len(self.cache) >= self.size:
            self.cache.popitem(last=False)
        self.cache[key] = value
