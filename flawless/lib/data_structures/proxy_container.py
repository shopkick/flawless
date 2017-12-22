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

import functools
import sys
if sys.version_info[0] <= 2:
    import new


class ProxyContainerMethodsMetaClass(type):

    def __init__(cls, name, bases, dct):
        func_names_to_proxy = dct.get('_proxyfunc_func_set_') or set(['__setitem__', '__getitem__', '__delitem__',
                                                                      '__contains__', '__iter__', '__len__'])
        for attr in func_names_to_proxy:
            if not hasattr(cls, attr):
                if sys.version_info[0] > 2:
                    # Python 3+
                    func = functools.partialmethod(dct['_proxyfunc_'], attr)
                    setattr(cls, attr, func)
                else:
                    # Python 2
                    func = (lambda attr:
                            lambda self, *args, **kwargs: dct['_proxyfunc_'](self, attr, *args, **kwargs))(attr)
                    setattr(cls, attr, new.instancemethod(func, None, cls))
        return super(ProxyContainerMethodsMetaClass, cls).__init__(name, bases, dct)
