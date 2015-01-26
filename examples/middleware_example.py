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

import flawless.client
from flawless.client.middleware import FlawlessMiddleware
import flawless.lib.config

# Django: Put the following in wsgi.py
# Pylons: Put the following in the make_app function in middleware.py
flawless.client.set_hostport("localhost:9028")
application = FlawlessMiddleware(application)



# There are three options for configuring the flawless client
# Option 1: Set flawless_hostport in the config file and call flawless.lib.config.init_config
flawless.lib.config.init_config("../config/flawless.cfg")

# Option 2: Call set_hostport
flawless.client.set_hostport("localhost:9028")
