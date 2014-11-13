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

import socket
import sys

try:
    import webob
except:
    pass

import flawless.client


class FlawlessMiddleware(object):
    """Middleware records errors to the error backend"""
    def __init__(self, app):
        self.app = app
        self.hostname = socket.gethostname()

    def __call__(self, environ, start_response):
        try:
            return self.app(environ, start_response)
        except:
            type, value, tb = sys.exc_info()
            reconstructed_req = self._reconstruct_request(environ)
            flawless.client.record_error(hostname=self.hostname, tb=tb, exception_message=repr(value),
                                         additional_info=reconstructed_req)
            raise value, None, tb

    def _reconstruct_request(self, environ):
        request_str = ""
        if "webob" in globals():
            request_str = str(webob.Request(environ))[:2000]
        else:
            req_parts = []
            method = environ.get("REQUEST_METHOD", "")
            path = environ.get("PATH_INFO", "")
            path += ("?" * bool(environ.get("QUERY_STRING"))) + environ.get("QUERY_STRING", "")

            req_parts.append("%s %s %s" % (method, path, environ.get("SERVER_PROTOCOL", "")))
            req_parts.append("Host: %s" % environ.get("HTTP_HOST", ""))
            req_parts.append("Referer: %s" % environ.get("HTTP_REFERER", ""))
            req_parts.append("Cookie: %s" % environ.get("HTTP_COOKIE", ""))
            req_parts.append("Content-Length: %s" % environ.get("CONTENT_LENGTH", ""))
            req_parts.append("User-Agent: %s" % environ.get("HTTP_USER_AGENT", ""))
            request_str = "\n".join(req_parts)

        return request_str
