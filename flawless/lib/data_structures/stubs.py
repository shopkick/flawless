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


class PersistentDictionaryStub(object):
  __metaclass__ = ProxyContainerMethodsMetaClass
  _proxyfunc_ = lambda attr, self, *args, **kwargs: getattr(self.dict, attr)(*args, **kwargs)

  def __init__(self, file_path):
    self.file_path = file_path

  def open(self):
    self.dict = dict()

  def sync(self):
    pass

  def close(self):
    pass

  def get_path(self):
    return self.file_path
