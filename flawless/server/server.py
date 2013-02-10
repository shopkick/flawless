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

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import functools
import logging
import os.path
from SocketServer import ThreadingMixIn
import sys
import urlparse

import flawless.lib.config
from flawless.server.service import FlawlessService

log = logging.getLogger(__name__)
config = flawless.lib.config.get()

class SimpleThreadedHTTPServer(ThreadingMixIn, HTTPServer):
  def attach_service(self, service):
    self.service = service

  def server_close(self):
    HTTPServer.server_close(self)
    self.service.errors_seen.sync()


class SimpleRequestHTTPHandler(BaseHTTPRequestHandler):

  def do_GET(self):
    parts = urlparse.urlparse(self.path)
    kwargs = dict(urlparse.parse_qsl(parts.query))
    ret = None

    try:
      if hasattr(self.server.service, parts.path[1:] or "index"):
        ret = getattr(self.server.service, parts.path[1:]  or "index")(**kwargs)
        self.send_response(200)
        self.send_header('Content-Length', len(ret or ""))
        self.send_header('Content-Type', 'text/html')
      else:
        self.send_response(404)
    except Exception as e:
      log.exception(e)
      self.send_response(500)
    finally:
      self.end_headers()
    if ret:
      self.wfile.write(ret)

  def do_POST(self):
    # Read in POST body
    parts = urlparse.urlparse(self.path)
    content_length = int(self.headers.getheader("Content-Length"))
    req_str = self.rfile.read(content_length)

    ret = None
    try:
      ret = getattr(self.server.service, parts.path[1:])(req_str)
      self.send_response(200)
      if ret:
        self.send_header('Content-Length', len(ret))
        self.send_header('Content-Type', 'text/html')
    except Exception as e:
      log.exception(e)
      self.send_response(500)
    finally:
      self.end_headers()

    if ret:
      self.wfile.write(ret)


def serve(conf_path):
  flawless.lib.config.init_config(conf_path)
  # Try and create datadir if it doesn't exist. For instance it might be in /tmp
  if not os.path.exists(config.data_dir_path):
    os.makedirs(config.data_dir_path)

  logging.basicConfig(level=getattr(logging, config.log_level), filename=config.log_file,
                      stream=sys.stderr)
  flawless_service = FlawlessService()
  server = SimpleThreadedHTTPServer(('', config.port), SimpleRequestHTTPHandler)
  server.attach_service(flawless_service)
  server.request_queue_size = 50
  try:
    server.serve_forever()
  except KeyboardInterrupt:
    server.server_close()

def main():
  conf_path = flawless.lib.config.default_path
  if len(sys.argv) > 1:
    conf_path = sys.argv[1]
  serve()


if __name__ == '__main__':
  main()
