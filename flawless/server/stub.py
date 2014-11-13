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

from flawless.server.api import Flawless


class FlawlessServiceStub(Flawless.Iface):

    def __init__(self):
        for func in [f for f in dir(self) if not f.startswith("_")]:
            getattr(self, func).__dict__["result"] = None
            getattr(self, func).__dict__["last_args"] = None
            getattr(self, func).__dict__["args_list"] = list()

    def _handle_stub(self, func, args):
        last_args = dict((k, v) for k, v in args.items() if k != "self")
        getattr(self, func).__dict__["last_args"] = last_args
        getattr(self, func).__dict__["args_list"].append(last_args)
        return getattr(self, func).__dict__["result"]

    def record_error(self, request):
        return self._handle_stub("record_error", locals())
