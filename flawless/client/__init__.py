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

import functools
import threading
import traceback
import os.path
import socket
import sys
import urllib2
import warnings


import flawless.client.default
import flawless.lib.config
import flawless.server.api as api


config = flawless.lib.config.get()


def _send_request(req):
  f = urllib2.urlopen(req, timeout=config.client_timeout)
  f.close()

def _get_backend_host():
  return config.flawless_hostport or flawless.client.default.hostport

def set_hostport(hostport):
  flawless.client.default.hostport = hostport

def record_error(hostname, traceback_list, exception_message,
                 error_threshold=None, additional_info=None):
  ''' Helper function to record errors to the flawless backend '''
  try:
    stack_lines = []
    for row in traceback_list:
      # TODO (john): May need to prepend site-packages to row[0] to get correct path
      abs_path = os.path.abspath(row[0])
      stack_lines.append(
        api.StackLine(filename=abs_path, line_number=row[1], function_name=row[2], text=row[3])
      )

    data = api.RecordErrorRequest(
        traceback=stack_lines,
        exception_message=exception_message,
        hostname=hostname,
        error_threshold=error_threshold,
        additional_info=additional_info,
    )

    req = urllib2.Request(url="http://%s/record_error" % _get_backend_host(),
                          data=data.dumps())
    _send_request(req)
  except:
    pass


def _wrap_function_with_error_decorator(func,
                                        save_current_stack_trace=True,
                                        reraise_exception=True,
                                        error_threshold=None):
  current_stack = []
  if save_current_stack_trace:
    current_stack = traceback.extract_stack()
  @functools.wraps(func)
  def wrapped_func_with_error_reporting(*args, **kwargs):
    if not _get_backend_host():
      warnings.warn("flawless server hostport not set", RuntimeWarning, stacklevel=2)
    try:
      return func(*args, **kwargs)
    except:
      type, value, tb = sys.exc_info()

      # Check to try and prevent multiple reports of the same exception
      if hasattr(value, "_flawless_already_caught"):
        if reraise_exception:
          raise value, None, tb
        else:
          return

      # Get trackback & report it
      traceback_list = traceback.extract_tb(tb)
      hostname = socket.gethostname()
      record_error(
          hostname=hostname,
          traceback_list=current_stack + traceback_list,
          exception_message=repr(value),
          error_threshold=error_threshold)

      # Reraise exception if so desired
      if reraise_exception:
        setattr(value, "_flawless_already_caught", True)
        raise value, None, tb
  return wrapped_func_with_error_reporting
