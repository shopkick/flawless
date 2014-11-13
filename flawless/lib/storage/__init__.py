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

from flawless.lib.storage.base import StorageInterface
from flawless.lib.storage.disk import DiskStorage

try:
    from flawless.lib.storage.redis import RedisStorage
except:
    pass
